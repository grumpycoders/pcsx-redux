#include <stdexcept>

#include "gl3w.h"

namespace {

#define GL3W_SYMBOL(x) \
void no##x() { \
    throw std::runtime_error("gl" #x " not loaded"); \
}

#include "gl3w-list.h"

#undef GL3W_SYMBOL

}

extern "C" GL3W_API void gl3wFillCppThrowers() {
	unsigned i = 0;

#define GL3W_SYMBOL(x) \
	if (!gl3wProcs.ptr[i]) gl3wProcs.ptr[i] = no##x; \
	i++;

#include "gl3w-list.h"

#undef GL3W_SYMBOL
}

extern "C" GL3W_API int gl3wIsCppThrower(GL3WglProc proc) {

#define GL3W_SYMBOL(x) \
	if (proc == no##x) \
		return 1;

#include "gl3w-list.h"

#undef GL3W_SYMBOL

	return 0;
}
