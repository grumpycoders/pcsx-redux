#pragma once

#include <atomic>
#include "reclaimer.h"

template <typename T>
class ConcreteReclaimer;

template <typename T>
class ConcurrentQueue {
	static_assert(std::is_copy_constructible_v<T>, "T requires copy constructor");
	struct Node;
	struct RegularNode;

	friend ConcreteReclaimer<T>;

public:
	ConcurrentQueue()
		: head_(new Node),
		tail_(head_.load(std::memory_order_relaxed)),
		size_(0) {}

	~ConcurrentQueue() {
		Node* p = head_.load(std::memory_order_acquire);
		while (p != nullptr) {
			Node* tmp = p;
			p = p->next.load(std::memory_order_acquire);
			tmp->Release();
		}
	}

	ConcurrentQueue(const ConcurrentQueue&) = delete;
	ConcurrentQueue(ConcurrentQueue&&) = delete;
	ConcurrentQueue& operator=(const ConcurrentQueue& other) = delete;
	ConcurrentQueue& operator=(ConcurrentQueue&& other) = delete;

	template <typename... Args>
	void Emplace(Args&&... args);

	void Enqueue(const T& value) {
		static_assert(std::is_copy_constructible<T>::value,
			"T must be copy constructible");
		Emplace(value);
	};

	void Enqueue(T&& value) {
		static_assert(std::is_constructible_v<T, T&&>,
			"T must be constructible with T&&");
		Emplace(std::forward<T>(value));
	}

	bool Dequeue(T& data);
	size_t size() const { return size_.load(std::memory_order_relaxed); }

private:
	Node* get_head() const { return head_.load(std::memory_order_acquire); }
	Node* get_tail() const { return tail_.load(std::memory_order_acquire); }

	// Get safe node and its next, ensure next is the succeed of node
	// and both pointer are safety.
	// REQUIRE: atomic_node is head_ or tail_.
	void AcquireSafeNodeAndNext(std::atomic<Node*>& atomic_node, Node** node_ptr,
		Node** next_ptr, HazardPointer& node_hp,
		HazardPointer& next_hp);

	// Invoke this function when the node can be reclaimed
	static void OnDeleteNode(void* ptr) { static_cast<Node*>(ptr)->Release(); }

	struct Node {
		Node() : next(nullptr) {}
		virtual ~Node() = default;

		virtual void Release() { delete this; }
		Node* get_next() const { return next.load(std::memory_order_acquire); }

		std::atomic<Node*> next;
	};

	struct RegularNode : Node {
		template <typename... Args>
		RegularNode(Args&&... args) : value(std::forward<Args>(args)...) {}
		~RegularNode() override = default;

		void Release() override { delete this; }

		T value;
	};

	std::atomic<Node*> head_;
	std::atomic<Node*> tail_;
	std::atomic<size_t> size_;
	static Reclaimer::HazardPointerList global_hp_list_;
};

template <typename T>
Reclaimer::HazardPointerList ConcurrentQueue<T>::global_hp_list_;

template <typename T>
class ConcreteReclaimer : public Reclaimer {
	friend ConcurrentQueue<T>;

private:
	ConcreteReclaimer(HazardPointerList& hp_list) : Reclaimer(hp_list) {}
	~ConcreteReclaimer() override = default;

	static ConcreteReclaimer<T>& GetInstance() {
		thread_local static ConcreteReclaimer reclaimer(
			ConcurrentQueue<T>::global_hp_list_);
		return reclaimer;
	}
};

template <typename T>
void ConcurrentQueue<T>::AcquireSafeNodeAndNext(std::atomic<Node*>& atomic_node,
	Node** node_ptr,
	Node** next_ptr,
	HazardPointer& node_hp,
	HazardPointer& next_hp) {
	Node* node = atomic_node.load(std::memory_order_acquire);
	Node* next;
	Node* temp_node;
	Node* temp_next;
	auto& reclaimer = ConcreteReclaimer<T>::GetInstance();
	do {
		do {
			// 1.UnMark old node;
			node_hp.UnMark();
			temp_node = node;
			// 2. Mark node.
			node_hp = HazardPointer(&reclaimer, node);
			node = atomic_node.load(std::memory_order_acquire);
			// 3. Make sure the node is still the one we mark before.
		} while (temp_node != node);
		// 4. UnMark old next.
		next_hp.UnMark();
		next = node->get_next();
		temp_next = next;
		// 5. Mark next.
		next_hp = HazardPointer(&reclaimer, next);
		next = node->get_next();
		// 6. Make sure the next is still the succeed of first.
	} while (temp_next != next);

	*node_ptr = node;
	*next_ptr = next;
}

template <typename T>
template <typename... Args>
void ConcurrentQueue<T>::Emplace(Args&&... args) {
	static_assert(std::is_constructible_v<T, Args&&...>,
		"T must be constructible with Args&&...");
	RegularNode* new_node = new RegularNode(std::forward<Args>(args)...);
	Node* tail;
	Node* next;
	HazardPointer tail_hp, next_hp;
	while (true) {
		AcquireSafeNodeAndNext(tail_, &tail, &next, tail_hp, next_hp);
		if (tail != get_tail()) continue;  // Are tail and next consistent?
		if (nullptr == next) {             // Was tail point to last node?
		  // Try to link node at the end of the linked list.
			if (tail->next.compare_exchange_strong(next, new_node)) break;
		}
		else {
			// Try to swing tail to the next node.
			tail_.compare_exchange_weak(tail, next);
		}
	}
	// Enqueue is done. Try to swing tail to the inserted node.
	tail_.compare_exchange_weak(tail, new_node);
	size_.fetch_add(1, std::memory_order_relaxed);
}

template <typename T>
bool ConcurrentQueue<T>::Dequeue(T& value) {
	HazardPointer head_hp;
	HazardPointer next_hp;
	Node* head;
	Node* next;
	Node* tail;
	while (true) {
		AcquireSafeNodeAndNext(head_, &head, &next, head_hp, next_hp);
		tail = get_tail();
		if (head != get_head()) continue;  // Are head, tail, and next consistent?
		if (nullptr == next) return false;  // Queue is empty;
		if (head == tail) {                // Is queue empty or tail falling behind?
			// Tail is falling behind. Try to advance it.
			tail_.compare_exchange_weak(tail, next);
		}
		else {
			// Try to swing head to the next node.
			if (head_.compare_exchange_strong(head, next)) break;
		}
	}
	size_.fetch_sub(1, std::memory_order_relaxed);
	auto& reclaimer = ConcreteReclaimer<T>::GetInstance();
	reclaimer.ReclaimLater(head, ConcurrentQueue<T>::OnDeleteNode);
	reclaimer.ReclaimNoHazardPointer();
	value = std::move(static_cast<RegularNode*>(next)->value);
	return true;
}
