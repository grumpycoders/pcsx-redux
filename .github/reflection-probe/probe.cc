#include <meta>

struct Probe {
    int a;
    float b;
};

consteval std::size_t memberCount() {
    return std::meta::nonstatic_data_members_of(^^Probe, std::meta::access_context::unchecked()).size();
}

static_assert(memberCount() == 2);
static_assert(std::meta::identifier_of(^^Probe::a) == "a");

int main() { return 0; }
