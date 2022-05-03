#include "reclaimer.h"

Reclaimer::~Reclaimer() {
	// The Reclaimer destruct when the thread exit

	// 1.Hand over the hazard pointer
	for (int i = 0; i < hp_list_.size(); ++i) {
		// If assert fired, you should make sure no pointer is marked as hazard
		// before thread exit
		assert(nullptr == hp_list_[i]->ptr.load(std::memory_order_relaxed));
		hp_list_[i]->flag.clear();
	}

	// 2.Make sure reclaim all no hazard pointers
	for (auto it = reclaim_map_.begin(); it != reclaim_map_.end();) {
		// Wait until pointer is no hazard
		while (Hazard(it->first)) {
			std::this_thread::yield();
		}

		ReclaimNode* node = it->second;
		node->delete_func(node->ptr);
		delete node;
		it = reclaim_map_.erase(it);
	}
}

Reclaimer::HPIndex Reclaimer::MarkHazard(void* ptr) {
	if (nullptr == ptr) return HP_INDEX_NULL;

	for (int i = 0; i < hp_list_.size(); ++i) {
		InternalHazardPointer* hp = hp_list_[i];
		if (nullptr == hp->ptr.load(std::memory_order_relaxed)) {
			hp->ptr.store(ptr, std::memory_order_release);
			return i;
		}
	}

	TryAcquireHazardPointer();
	int index = hp_list_.size() - 1;
	hp_list_[index]->ptr.store(ptr, std::memory_order_release);
	return index;
}

void Reclaimer::ReclaimNoHazardPointer() {
	if (reclaim_map_.size() < kCoefficient * global_hp_list_.get_size()) {
		return;
	}

	// Used to speed up the inspection of the ptr.
	std::unordered_set<void*> not_allow_delete_set;
	std::atomic<InternalHazardPointer*>& head = global_hp_list_.head;
	InternalHazardPointer* p = head.load(std::memory_order_acquire);
	do {
		void* const ptr = p->ptr.load(std::memory_order_consume);
		if (nullptr != ptr) {
			not_allow_delete_set.insert(ptr);
		}
		p = p->next.load(std::memory_order_acquire);
	} while (p);

	for (auto it = reclaim_map_.begin(); it != reclaim_map_.end();) {
		if (not_allow_delete_set.find(it->first) == not_allow_delete_set.end()) {
			ReclaimNode* node = it->second;
			node->delete_func(node->ptr);
			reclaim_pool_.Push(node);
			it = reclaim_map_.erase(it);
		}
		else {
			++it;
		}
	}
}

bool Reclaimer::Hazard(void* const ptr) {
	std::atomic<InternalHazardPointer*>& head = global_hp_list_.head;
	InternalHazardPointer* p = head.load(std::memory_order_acquire);
	do {
		if (p->ptr.load(std::memory_order_consume) == ptr) {
			return true;
		}
		p = p->next.load(std::memory_order_acquire);
	} while (p != nullptr);

	return false;
}

void Reclaimer::TryAcquireHazardPointer() {
	std::atomic<InternalHazardPointer*>& head = global_hp_list_.head;
	InternalHazardPointer* p = head.load(std::memory_order_acquire);
	InternalHazardPointer* hp = nullptr;
	do {
		// Try to get the idle hazard pointer.
		if (!p->flag.test_and_set()) {
			hp = p;
			break;
		}
		p = p->next.load(std::memory_order_acquire);
	} while (p != nullptr);

	if (nullptr == hp) {
		// No idle hazard pointer, allocate new one.
		InternalHazardPointer* new_head = new InternalHazardPointer();
		new_head->flag.test_and_set();
		hp = new_head;
		global_hp_list_.size.fetch_add(1, std::memory_order_release);
		InternalHazardPointer* old_head = head.load(std::memory_order_acquire);
		do {
			new_head->next = old_head;
		} while (!head.compare_exchange_weak(old_head, new_head,
			std::memory_order_release,
			std::memory_order_relaxed));
	}
	hp_list_.push_back(hp);
}
