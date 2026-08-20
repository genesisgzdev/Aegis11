#include "../include/Core/RAII.hpp"
#include "../include/Core/Logger.hpp"
#include "../include/Core/PolicyEngine.hpp"
#include "../include/Core/ProcessHost.hpp"
#include "../include/Core/SysInfo.hpp"
#include "../include/CLI/ArgumentParser.hpp"
#include "../include/UI/InteractiveShell.hpp"
#include "../include/Modules/AppxManager.hpp"
#include "../include/Modules/TaskManager.hpp"
#include "../include/Modules/NetworkWfp.hpp"
#include "../include/Modules/ServiceManager.hpp"
#include "../include/Modules/FirewallManager.hpp"
#include "../include/Modules/DataPurge.hpp"
#include "../include/Modules/NetworkOptimizer.hpp"
#include "../include/Modules/Reinforcement.hpp"
#include <iostream>
#include <algorithm>
#include <roapi.h>

using namespace Aegis::Core;
using namespace Aegis::Modules;
using namespace Aegis::UI;

int main(int argc, char* argv[]) {
    if (GetConsoleWindow() == NULL) {
        AllocConsole();
        FILE* fp; freopen_s(&fp, "CONOUT$", "w", stdout); freopen_s(&fp, "CONOUT$", "w", stderr); freopen_s(&fp, "CONIN$", "r", stdin);
    }
    ProcessHost::SetConsoleState();
    if (!ProcessHost::EnforceSingleInstance()) return 1;
    const auto runConfig = ArgumentParser::Parse(argc, argv);
    if (runConfig.show_help) {
        ArgumentParser::PrintHelp();
        return 0;
    }
    if (runConfig.invalid) {
        std::cerr << "[!] Invalid command-line option or missing option value. Use --help.\n";
        return 2;
    }

    // Initialize Windows Runtime (WinRT) for In-Process isolation of the PackageManager COM Interface
    HRESULT hrRo = RoInitialize(RO_INIT_MULTITHREADED);
    if (FAILED(hrRo)) {
        std::cout << "[!] Warning: WinRT Subsystem failed to initialize. Modern Appx logic may be degraded.\n";
    }

    Logger log;
    PolicyEngine engine(log);
    AppxManager am(log);
    TaskManager tm(log);
    NetworkWfp nw(log);
    ServiceManager sm(log);
    FirewallManager fm(log);
    DataPurge dp(log);
    NetworkOptimizer no(log, engine);
    Reinforcement rf(log);

    // CLI Parameter Handling
    const bool reconcile = std::find_if(argv + 1, argv + argc, [](const char* arg) {
        return std::string(arg) == "--reconcile";
    }) != argv + argc;
    if (reconcile) {
        log.SetTraceId("RECONCILE");
        log.Log(LogLevel::INFO, "SYS", 100, "Automated Reconciliation Triggered.");
        engine.LoadAndRecover();
        sm.EnforcePolicy(false);
        tm.DisableTelemetryTasks();
        return 0;
    }
    if (runConfig.simulate) {
        sm.EnforcePolicy(true);
        return 0;
    }
    if (runConfig.apply) {
        sm.EnforcePolicy(false);
        return 0;
    }
    if (!runConfig.snapshot_file.empty() || !runConfig.restore_file.empty()) {
        std::cerr << "[!] Snapshot/restore CLI plumbing is not implemented; refusing a false success.\n";
        return 3;
    }

    InteractiveShell shell(log, engine, am, tm, nw, sm, fm, dp, no);
    
    // Register Reinforcement Task on every interactive run to ensure persistence
    rf.RegisterSelfHealingTask();

    shell.Run();

    ProcessHost::TeardownCOM();
    RoUninitialize();
    return 0;
}
