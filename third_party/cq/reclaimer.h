#pragma once

#include <atomic>
#include <cassert>
#include <functional>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

class HazardPointer;

class Reclaimer {
	typedef int HPIndex;
	friend HazardPointer;

private:
	// A coefficient that used to calcuate the max number
	// of reclaim node in reclaim list.
	static const int kCoefficient = 4 + 1 / 4;
	static const HPIndex HP_INDEX_NULL = -1;

	struct InternalHazardPointer {
		InternalHazardPointer() : flag(), ptr(nullptr), next(nullptr) { flag.clear(); }
		~InternalHazardPointer() {}

		InternalHazardPointer(const InternalHazardPointer& other) = delete;
		InternalHazardPointer(InternalHazardPointer&& other) = delete;
		InternalHazardPointer& operator=(const InternalHazardPointer& other) =
			delete;
		InternalHazardPointer& operator=(InternalHazardPointer&& other) = delete;

		std::atomic_flag flag;
		// We must use atomic pointer to ensure the modification
		// is visible to other threads.
		std::atomic<void*> ptr;
		std::atomic<InternalHazardPointer*> next;
	};

public:
	struct HazardPointerList {
		HazardPointerList() : head(new InternalHazardPointer()), size(0) {}
		~HazardPointerList() {
			// HazardPointerList destruct when program exit.
			InternalHazardPointer* p = head.load(std::memory_order_acquire);
			while (p) {
				InternalHazardPointer* temp = p;
				p = p->next.load(std::memory_order_consume);
				delete temp;
			}
		}

		size_t get_size() const { return size.load(std::memory_order_consume); }

		std::atomic<InternalHazardPointer*> head;
		std::atomic<int> size;
	};

	Reclaimer(const Reclaimer&) = delete;
	Reclaimer(Reclaimer&&) = delete;
	Reclaimer& operator=(const Reclaimer&) = delete;
	Reclaimer& operator=(Reclaimer&&) = delete;

	// Mark ptr as hazard.
	HPIndex MarkHazard(void* ptr);
	void UnMarkHazard(HPIndex index) {
		if (index == HP_INDEX_NULL) return;

		assert(index >= 0 && index < hp_list_.size());
		hp_list_[index]->ptr.store(nullptr, std::memory_order_release);
	}

	// Get ptr that marked as hazard at the index of hazard_pointers_ array.
	void* GetHazardPtr(HPIndex index) {
		if (index == HP_INDEX_NULL) return nullptr;

		assert(index >= 0 && index < hp_list_.size());
		return hp_list_[index]->ptr.load(std::memory_order_relaxed);
	}

	// If ptr is hazard then reclaim it later.
	void ReclaimLater(void* const ptr, std::function<void(void*)>&& func) {
		ReclaimNode* new_node = reclaim_pool_.Pop();
		new_node->ptr = ptr;
		new_node->delete_func = std::move(func);
		reclaim_map_.insert(std::make_pair(ptr, new_node));
	}

	// Try to reclaim all no hazard pointers.
	void ReclaimNoHazardPointer();

protected:
	Reclaimer(HazardPointerList& hp_list) : global_hp_list_(hp_list) {}
	virtual ~Reclaimer();

private:
	// Check if the ptr is hazard.
	bool Hazard(void* const ptr);
	void TryAcquireHazardPointer();

	struct ReclaimNode {
		ReclaimNode() : ptr(nullptr), next(nullptr), delete_func(nullptr) {}
		~ReclaimNode() {}

		void* ptr;
		ReclaimNode* next;
		std::function<void(void*)> delete_func;
	};

	// Reuse ReclaimNode
	struct ReclaimPool {
		ReclaimPool() : head(new ReclaimNode()) {}
		~ReclaimPool() {
			ReclaimNode* temp;
			while (head) {
				temp = head;
				head = head->next;
				delete temp;
			}
		}

		void Push(ReclaimNode* node) {
			node->next = head;
			head = node;
		}

		ReclaimNode* Pop() {
			if (nullptr == head->next) {
				return new ReclaimNode();
			}

			ReclaimNode* temp = head;
			head = head->next;
			temp->next = nullptr;
			return temp;
		}

		ReclaimNode* head;
	};

	std::vector<InternalHazardPointer*> hp_list_;
	std::unordered_map<void*, ReclaimNode*> reclaim_map_;
	ReclaimPool reclaim_pool_;
	HazardPointerList& global_hp_list_;
};

// Use Hazard Pointer in RAII style.
class HazardPointer {
public:
	HazardPointer() : reclaimer_(nullptr), index(Reclaimer::HP_INDEX_NULL) {}
	HazardPointer(Reclaimer* reclaimer_, void* ptr)
		: reclaimer_(reclaimer_), index(reclaimer_->MarkHazard(ptr)) {}

	~HazardPointer() { UnMark(); }

	HazardPointer(const HazardPointer& other) = delete;
	HazardPointer(HazardPointer&& other) {
		*this = std::move(other);
	}

	HazardPointer& operator=(const HazardPointer& other) = delete;
	HazardPointer& operator=(HazardPointer&& other) {
		reclaimer_ = other.reclaimer_;
		index = other.index;

		// If move assign is called, we must disable the other's index to avoid
		// incorrectly unmark index when other destruct.
		other.index = Reclaimer::HP_INDEX_NULL;
		return *this;
	}

	void UnMark() { reclaimer_->UnMarkHazard(index); }

public:
	Reclaimer* reclaimer_;
	Reclaimer::HPIndex index;
};
