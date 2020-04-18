#include <iostream>
#include <malloc.h>
#include <crtdbg.h>
#include <string>

/*
Example code for memory leak detection with GTA.
See https://github.com/csoltenborn/GoogleTestAdapter#evaluating-the-test-executables-exit-code for usage.
*/

// construct new singleton instance on first allocation, to perform memory leak reporting on destruction
// construction is performed in overridden 'new' operators to ensure its initialized before first allocation
// based on code provided by https://github.com/alfredskpoon (see https://github.com/csoltenborn/GoogleTestAdapter/issues/266)
namespace gta_leak_detection
{
    bool is_run_by_gta = false;
    int result_of_run_all_tests = -1;

    class EnableLeakCheck  // NOLINT(hicpp-special-member-functions, cppcoreguidelines-special-member-functions)
    {
    public:
        static void Initialize()
        {
            static EnableLeakCheck leakReporter;
        }
    private:
        EnableLeakCheck() = default;

        ~EnableLeakCheck()  // NOLINT(bugprone-exception-escape)
        {
            _CrtDumpMemoryLeaks();

#ifdef _DEBUG
            // exit point 1 - reached in Debug mode if no memory leaks have been found
            std::cout << "No memory leaks have been found.";
            exit(0);
#endif // _DEBUG
        }
    };


    template<typename T, size_t N> inline size_t lengthof(T const (&array)[N]) { return N; }
    template<int N> struct lengthof_sizer
    {
        unsigned char count[N];
    };
    template< class T, int N > inline lengthof_sizer<N> lengthof_get_sizer(T const (&array)[N]) { return lengthof_sizer<N>(); }
#define LENGTHOF( a ) sizeof( lengthof_get_sizer( a ).count )

    class ShutdownReportHook
    {
    public:
        static void RegisterMemoryLeakAssertOnExit()
        {
            _CrtSetReportHookW2(_CRT_RPTHOOK_INSTALL, &RunHook_);
        }
    private:
        static int RunHook_
        (
            int   reportType,
            wchar_t* message,
            int* returnValue
        )
        {
            static bool reportingLeaks_ = false;

            // Detect when the memory leak dump is starting, and flag for special processing of leak reports.
            const wchar_t szStartDumpString[] = L"Detected memory leaks!";  //CRT is hard coded to say "Detected memory leaks!\n" in the memory leak report
            if (::wcsncmp(message, szStartDumpString, LENGTHOF(szStartDumpString) - 1) == 0)
            {
                reportingLeaks_ = true;
                std::wcout << std::wstring(message);

                // TODO remove if gtest "memory leaks" have been fixed
                if (result_of_run_all_tests != 0 && is_run_by_gta)
                {
                    std::cout << "GTA_EXIT_CODE_SKIP\n";
                    std::cout << "\nTest result is 'Skipped' due to some weaknesses of Google Test 1.8.1 and crtdbg.h: leak detection results are only reliable if all executed tests have passed.\n\n";
                }

                return 0;
            }

            // Detect when the memory leak dump is done, and then exit the process with an error code.
            const wchar_t szDoneDumpString[] = L"Object dump complete.";    //CRT is hard coded to say "Object dump complete.\n" in the memory leak report
            if (::wcsncmp(message, szDoneDumpString, LENGTHOF(szDoneDumpString) - 1) == 0)
            {
                std::wcout << std::wstring(szDoneDumpString);

                // exit point 2 - reached in case of memory leaks (and at the end of the leak check output)
                exit(1);
            }

            // decide if we want to print the message or not...
            if (reportingLeaks_)
            {
                std::wcout << std::wstring(message);
            }

            return 0;
        }
    };

    struct InitCleanupOnExit
    {
        InitCleanupOnExit()
        {
            std::atexit(&CleanupOnExit_);   // Cleanup event sink on program shutdown.
        }

    private:

        static void CleanupOnExit_()
        {
            // Memory leaks reports happen on shutdown after this point, so force them to go out via stderr
            // so any parent process will see it as an error.
            ShutdownReportHook::RegisterMemoryLeakAssertOnExit();
        }

    } gInitCleanupOnExit;


    int PerformLeakDetection(int argc, char** argv, int resultOfRunAllTests)
    {
        result_of_run_all_tests = resultOfRunAllTests;

        std::string option("-is_run_by_gta");
        for (int i = 0; i < argc; i++)
        {
            if (strncmp(argv[i], option.c_str(), strlen(option.c_str())) == 0)
            {
                is_run_by_gta = true;
                break;
            }
        }

        // use the rest of the output as message of exit code test
        if (is_run_by_gta)
            std::cout << "GTA_EXIT_CODE_OUTPUT_BEGIN\n";

        // exit point 3
        // memory leak detection will do exit(1) if memory leaks are found, and exit(0) if not
        // this exit is thus taken only if compiled with Release configuration
        // since test outcome is Skipped in this case, we can just return the result of RUN_ALL_TESTS()
#ifndef _DEBUG
        if (is_run_by_gta)
        {
            std::cout << "GTA_EXIT_CODE_SKIP\n";
            std::cout << "Memory leak detection is only performed if compiled with Debug configuration.\n";
        }
#endif
        return result_of_run_all_tests;
    }
}


#undef new

void* operator new(size_t size)  // NOLINT(cert-dcl54-cpp, misc-new-delete-overloads, hicpp-new-delete-operators)
 //throw( std::bad_alloc )
{
    gta_leak_detection::EnableLeakCheck::Initialize();
    return malloc(size);
}

void* operator new[](size_t const size)  // NOLINT(cert-dcl54-cpp, misc-new-delete-overloads, hicpp-new-delete-operators)
{
    gta_leak_detection::EnableLeakCheck::Initialize();
    return operator new(size);
}
