#include "../include/Core/RAII.hpp"
#include "../include/Core/Logger.hpp"
#include "../include/Core/PolicyEngine.hpp"
#include "../include/Core/StateEngine.hpp"
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
using namespace Aegis::CLI;
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
    TaskManager tm(log);
    RegistryManager rm(log);
    ServiceManager sm(log);

    // CLI Parameter Handling
    if (runConfig.simulate) {
        sm.EnforcePolicy(true);
        return 0;
    }
    if (runConfig.apply) {
        sm.EnforcePolicy(false);
        return 0;
    }
    if (!runConfig.snapshot_file.empty()) {
        Aegis::Engine::StateController state(log, sm, rm, tm);
        state.CreateBaseline(runConfig.snapshot_file);
        return 0;
    }
    if (!runConfig.restore_file.empty()) {
        std::cerr << "[!] Restore is not implemented; refusing to claim a rollback from a baseline file.\n";
        return 3;
    }

    PolicyEngine engine(log);
    AppxManager am(log);
    NetworkWfp nw(log);
    FirewallManager fm(log);
    DataPurge dp(log);
    NetworkOptimizer no(log, engine);

    if (runConfig.reconcile) {
        log.SetTraceId("RECONCILE");
        log.Log(LogLevel::INFO, "SYS", 100, "Automated Reconciliation Triggered.");
        // PolicyEngine already loads and recovers the durable journal in its
        // constructor. Keep reconciliation single-entry so a recovery result
        // is not replayed immediately by the same process.
        sm.EnforcePolicy(false);
        tm.DisableTelemetryTasks();
        return 0;
    }

    Reinforcement rf(log);
    InteractiveShell shell(log, engine, am, tm, nw, sm, fm, dp, no);
    
    // Register Reinforcement Task on every interactive run to ensure persistence
    rf.RegisterSelfHealingTask();

    shell.Run();

    ProcessHost::TeardownCOM();
    RoUninitialize();
    return 0;
}
