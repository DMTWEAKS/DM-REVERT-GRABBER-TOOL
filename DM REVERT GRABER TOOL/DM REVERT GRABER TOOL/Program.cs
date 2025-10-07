using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace RegistryBackupTool
{
    class Program
    {
        static string logFile = $"backup_log_{DateTime.Now:yyyyMMdd_HHmmss}.txt";

        static void Main(string[] args)
        {
            if (!IsAdministrator())
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("╔════════════════════════════════════════════════════════════╗");
                Console.WriteLine("║  ERROR: This tool requires Administrator privileges!       ║");
                Console.WriteLine("║  Please run as Administrator and try again.                ║");
                Console.WriteLine("╚════════════════════════════════════════════════════════════╝");
                Console.ResetColor();
                LogToFile("ERROR: Application started without administrator privileges");
                Console.WriteLine("\nPress any key to exit...");
                Console.ReadKey();
                return;
            }

            Console.WriteLine("Registry Backup Tool");
            Console.WriteLine("====================\n");
            LogToFile("Application started successfully with administrator privileges");

            var cmdArgs = ParseCommandLineArgs(args);

            if (cmdArgs.ContainsKey("--help") || cmdArgs.ContainsKey("-h"))
            {
                ShowHelp();
                return;
            }

            bool verbose = cmdArgs.ContainsKey("--verbose") || cmdArgs.ContainsKey("-v");

            string configFile = cmdArgs.ContainsKey("--config") ? cmdArgs["--config"] : "registry_paths.json";
            string outputFile = cmdArgs.ContainsKey("--output") ? cmdArgs["--output"] : $"registry_backup_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
            string revertScriptFile = $"revert_script_{DateTime.Now:yyyyMMdd_HHmmss}.bat";

            string[] possibleFiles = {
                configFile,
                "registry_paths.json",
                "registry_paths.txt",
                "tweaks.txt",
                "reg_commands.txt"
            };

            string foundFile = null;
            foreach (var file in possibleFiles)
            {
                if (File.Exists(file))
                {
                    foundFile = file;
                    configFile = file;
                    break;
                }
            }

            if (foundFile == null)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Error: No configuration file found!");
                Console.ResetColor();
                Console.WriteLine("\nSearched for:");
                Console.WriteLine("  - registry_paths.json");
                Console.WriteLine("  - registry_paths.txt");
                Console.WriteLine("  - tweaks.txt");
                Console.WriteLine("  - reg_commands.txt");
                Console.WriteLine("\nPlease create a configuration file with your registry tweaks.");
                Console.WriteLine("See README.md for configuration format examples.");
                LogToFile("ERROR: No config file found");
                Console.WriteLine("\nPress any key to exit...");
                Console.ReadKey();
                return;
            }

            Console.WriteLine($"Using config file: {foundFile}\n");
            LogToFile($"Using config file: {foundFile}");

            List<RegistryEntry> registryEntries;
            string fileContent = File.ReadAllText(configFile);

            if (fileContent.TrimStart().StartsWith("{") || configFile.EndsWith(".json"))
            {
                Console.WriteLine("Detected JSON format");
                registryEntries = ParseJsonConfig(configFile);
            }
            else if (fileContent.Contains("reg add") || fileContent.Contains("Reg.exe add"))
            {
                Console.WriteLine("Detected reg add commands format");
                registryEntries = ParseRegCommands(configFile);
            }
            else if (fileContent.Contains("powercfg") || fileContent.Contains("netsh"))
            {
                Console.WriteLine("Detected PowerCfg/Netsh commands - extracting registry equivalents");
                registryEntries = ParsePowerCfgNetshCommands(configFile);
            }
            else
            {
                Console.WriteLine("Detected simple text format");
                registryEntries = ParseTextConfig(configFile);
            }

            if ((fileContent.Contains("powercfg") || fileContent.Contains("netsh")) && fileContent.Contains("reg add"))
            {
                Console.WriteLine("Also parsing reg add commands from file");
                var regEntries = ParseRegCommands(configFile);
                registryEntries.AddRange(regEntries);
            }

            Console.WriteLine("\nValidating configuration...");
            var validationErrors = ValidateConfig(registryEntries);
            if (validationErrors.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"\n⚠ Configuration validation found {validationErrors.Count} issue(s):");
                foreach (var error in validationErrors)
                {
                    Console.WriteLine($"  - {error}");
                    LogToFile($"VALIDATION WARNING: {error}");
                }
                Console.ResetColor();
                Console.Write("\nContinue anyway? (y/n): ");
                if (Console.ReadLine()?.ToLower() != "y")
                {
                    Console.WriteLine("Operation cancelled by user.");
                    LogToFile("Operation cancelled due to validation errors");
                    return;
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("✓ Configuration validated successfully");
                Console.ResetColor();
            }

            Console.WriteLine($"\nFound {registryEntries.Count} registry modifications to backup.\n");
            LogToFile($"Found {registryEntries.Count} registry entries to process");

            var backupData = new List<RegistryBackup>();
            int successCount = 0;
            int failCount = 0;

            for (int i = 0; i < registryEntries.Count; i++)
            {
                var entry = registryEntries[i];

                if (verbose)
                {
                    Console.WriteLine($"\nProcessing [{i + 1}/{registryEntries.Count}]: {entry.Path}\\{entry.ValueName}");
                }

                var backup = BackupRegistryValue(entry);
                backupData.Add(backup);

                if (backup.Success)
                {
                    successCount++;
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write("✓");
                    Console.ResetColor();
                    if (verbose)
                    {
                        Console.WriteLine($" Value: {FormatValue(backup.OriginalValue, backup.OriginalValueKind)}");
                    }
                    LogToFile($"SUCCESS: Backed up {entry.Path}\\{entry.ValueName}");
                }
                else
                {
                    failCount++;
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.Write("⚠");
                    Console.ResetColor();
                    if (verbose)
                    {
                        Console.WriteLine($" Error: {backup.ErrorMessage}");
                    }
                    LogToFile($"WARNING: Failed to backup {entry.Path}\\{entry.ValueName} - {backup.ErrorMessage}");
                }

                ShowProgress(i + 1, registryEntries.Count, entry.ValueName);
            }

            Console.WriteLine("\n");

            SaveBackupData(backupData, outputFile);
            GenerateRevertScript(backupData, revertScriptFile);

            string psScriptFile = revertScriptFile.Replace(".bat", ".ps1");
            GenerateRevertPowerShellScript(backupData, psScriptFile);

            string defaultValuesFile = $"default_values_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
            GenerateDefaultValuesFile(backupData, defaultValuesFile);

            Console.WriteLine($"\n==========================================");
            Console.WriteLine($"Backup Complete!");
            Console.WriteLine($"Success: {successCount} | Not Found: {failCount}");
            Console.WriteLine($"\nFiles generated:");
            Console.WriteLine($"  • Backup (Text): {outputFile}");
            Console.WriteLine($"  • Revert (Batch): {revertScriptFile}");
            Console.WriteLine($"  • Revert (PowerShell): {psScriptFile}");
            Console.WriteLine($"  • Default values: {defaultValuesFile}");

            string jsonOutput = $"registry_backup_{DateTime.Now:yyyyMMdd_HHmmss}.json";
            SaveBackupDataJson(backupData, jsonOutput);
            Console.WriteLine($"  • Backup (JSON): {jsonOutput}");
            Console.WriteLine($"  • Log: {logFile}");

            LogToFile($"Backup completed - Success: {successCount}, Failed: {failCount}");

            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }

        static bool IsAdministrator()
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        static Dictionary<string, string> ParseCommandLineArgs(string[] args)
        {
            var result = new Dictionary<string, string>();

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].StartsWith("--") || args[i].StartsWith("-"))
                {
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                    {
                        result[args[i]] = args[i + 1];
                        i++;
                    }
                    else
                    {
                        result[args[i]] = "true";
                    }
                }
            }

            return result;
        }

        static void ShowHelp()
        {
            Console.WriteLine("Registry Backup Tool - Command Line Options");
            Console.WriteLine("============================================\n");
            Console.WriteLine("Usage: RegistryBackupTool.exe [options]\n");
            Console.WriteLine("Options:");
            Console.WriteLine("  --config <file>     Specify config file (default: registry_paths.json)");
            Console.WriteLine("  --output <file>     Specify output file");
            Console.WriteLine("  --verbose, -v       Show detailed progress information");
            Console.WriteLine("  --help, -h          Show this help message");
            Console.WriteLine("\nExample:");
            Console.WriteLine("  RegistryBackupTool.exe --config mytweaks.txt --verbose");
            Console.WriteLine("\nFor more information, visit:");
            Console.WriteLine("  https://github.com/yourusername/RegistryBackupTool");
        }

        static void LogToFile(string message, string customLogFile = null)
        {
            try
            {
                string logPath = customLogFile ?? logFile;
                string logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}";
                File.AppendAllText(logPath, logEntry + Environment.NewLine);
            }
            catch
            {
            }
        }

        static void ShowProgress(int current, int total, string item)
        {
            int barWidth = 40;
            int progress = (int)((double)current / total * barWidth);
            int percentage = (int)((double)current / total * 100);

            Console.Write("\r[");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write(new string('█', progress));
            Console.ResetColor();
            Console.Write(new string('░', barWidth - progress));
            Console.Write($"] {percentage}% ({current}/{total})");

            if (current == total)
            {
                Console.WriteLine();
            }
        }

        static List<string> ValidateConfig(List<RegistryEntry> entries)
        {
            var errors = new List<string>();
            var seenPaths = new HashSet<string>();

            foreach (var entry in entries)
            {
                if (string.IsNullOrEmpty(entry.Path))
                {
                    errors.Add($"Empty path for value: {entry.ValueName}");
                    continue;
                }

                if (string.IsNullOrEmpty(entry.ValueName))
                {
                    errors.Add($"Empty value name for path: {entry.Path}");
                    continue;
                }

                var upperPath = entry.Path.ToUpper();
                if (!upperPath.StartsWith("HKEY") && !upperPath.StartsWith("HK"))
                {
                    errors.Add($"Invalid registry hive: {entry.Path}");
                }

                if (upperPath.Contains("\\SAM\\") || upperPath.Contains("\\SECURITY\\"))
                {
                    errors.Add($"WARNING: Sensitive system path detected: {entry.Path}");
                }

                if (upperPath.Contains("\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\WINLOGON"))
                {
                    errors.Add($"WARNING: Critical security path detected: {entry.Path}");
                }

                string pathKey = $"{entry.Path}\\{entry.ValueName}";
                if (seenPaths.Contains(pathKey))
                {
                    errors.Add($"Duplicate entry found: {pathKey}");
                }
                else
                {
                    seenPaths.Add(pathKey);
                }

                string[] validTypes = { "REG_SZ", "REG_DWORD", "REG_QWORD", "REG_BINARY", "REG_MULTI_SZ", "REG_EXPAND_SZ" };
                if (!string.IsNullOrEmpty(entry.Type) && !validTypes.Contains(entry.Type.ToUpper()))
                {
                    errors.Add($"Unknown registry type '{entry.Type}' for {entry.Path}\\{entry.ValueName}");
                }
            }

            return errors;
        }

        static void GenerateRevertPowerShellScript(List<RegistryBackup> backups, string scriptFile)
        {
            var sb = new StringBuilder();
            sb.AppendLine("# Registry Revert Script (PowerShell)");
            sb.AppendLine($"# Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine("# Requires Administrator privileges");
            sb.AppendLine();
            sb.AppendLine("if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {");
            sb.AppendLine("    Write-Error 'This script must be run as Administrator'");
            sb.AppendLine("    Read-Host 'Press Enter to exit'");
            sb.AppendLine("    exit 1");
            sb.AppendLine("}");
            sb.AppendLine();
            sb.AppendLine("Write-Host 'Registry Revert Script' -ForegroundColor Cyan");
            sb.AppendLine("Write-Host '=====================' -ForegroundColor Cyan");
            sb.AppendLine("Write-Host ''");
            sb.AppendLine();

            string currentCategory = null;
            foreach (var backup in backups)
            {
                if (backup.Entry.Category != currentCategory)
                {
                    currentCategory = backup.Entry.Category;
                    sb.AppendLine();
                    sb.AppendLine($"Write-Host 'Category: {currentCategory}' -ForegroundColor Yellow");
                }

                if (backup.Success && backup.ValueExists)
                {
                    var psPath = ConvertToPowerShellPath(backup.Entry.Path);
                    var value = FormatValueForPowerShell(backup.OriginalValue, backup.OriginalValueKind);
                    var psType = ConvertToPowerShellType(backup.OriginalValueKind);

                    sb.AppendLine($"try {{");
                    sb.AppendLine($"    Set-ItemProperty -Path '{psPath}' -Name '{backup.Entry.ValueName}' -Value {value} -Type {psType} -Force -ErrorAction Stop");
                    sb.AppendLine($"    Write-Host '✓ Restored: {backup.Entry.Path}\\{backup.Entry.ValueName}' -ForegroundColor Green");
                    sb.AppendLine($"}} catch {{");
                    sb.AppendLine($"    Write-Host '✗ Failed: {backup.Entry.Path}\\{backup.Entry.ValueName}' -ForegroundColor Red");
                    sb.AppendLine($"    Write-Host \"  Error: $($_.Exception.Message)\" -ForegroundColor Red");
                    sb.AppendLine($"}}");
                }
                else if (!backup.ValueExists)
                {
                    var psPath = ConvertToPowerShellPath(backup.Entry.Path);
                    sb.AppendLine($"try {{");
                    sb.AppendLine($"    Remove-ItemProperty -Path '{psPath}' -Name '{backup.Entry.ValueName}' -Force -ErrorAction Stop");
                    sb.AppendLine($"    Write-Host '✓ Removed: {backup.Entry.Path}\\{backup.Entry.ValueName}' -ForegroundColor Green");
                    sb.AppendLine($"}} catch {{");
                    sb.AppendLine($"    Write-Host '⚠ Not found (already removed): {backup.Entry.Path}\\{backup.Entry.ValueName}' -ForegroundColor Yellow");
                    sb.AppendLine($"}}");
                }
            }

            sb.AppendLine();
            sb.AppendLine("Write-Host ''");
            sb.AppendLine("Write-Host 'Revert complete!' -ForegroundColor Green");
            sb.AppendLine("Read-Host 'Press Enter to exit'");

            File.WriteAllText(scriptFile, sb.ToString());
        }

        static string ConvertToPowerShellPath(string regPath)
        {
            return "Registry::" + regPath
                .Replace("HKLM\\", "HKEY_LOCAL_MACHINE\\")
                .Replace("HKCU\\", "HKEY_CURRENT_USER\\")
                .Replace("HKCR\\", "HKEY_CLASSES_ROOT\\")
                .Replace("HKU\\", "HKEY_USERS\\")
                .Replace("HKCC\\", "HKEY_CURRENT_CONFIG\\");
        }

        static string ConvertToPowerShellType(RegistryValueKind kind)
        {
            return kind switch
            {
                RegistryValueKind.String => "String",
                RegistryValueKind.DWord => "DWord",
                RegistryValueKind.QWord => "QWord",
                RegistryValueKind.Binary => "Binary",
                RegistryValueKind.MultiString => "MultiString",
                RegistryValueKind.ExpandString => "ExpandString",
                _ => "String"
            };
        }

        static string FormatValueForPowerShell(object value, RegistryValueKind kind)
        {
            if (value == null)
                return "$null";

            switch (kind)
            {
                case RegistryValueKind.Binary:
                    var bytes = (byte[])value;
                    return $"([byte[]]@({string.Join(",", bytes.Select(b => $"0x{b:X2}"))}))";

                case RegistryValueKind.DWord:
                case RegistryValueKind.QWord:
                    return Convert.ToInt64(value).ToString();

                case RegistryValueKind.MultiString:
                    var multiStr = (string[])value;
                    var escaped = multiStr.Select(s => $"'{s.Replace("'", "''")}'");
                    return $"@({string.Join(",", escaped)})";

                case RegistryValueKind.String:
                case RegistryValueKind.ExpandString:
                default:
                    string strValue = value.ToString().Replace("'", "''");
                    return $"'{strValue}'";
            }
        }

        static List<RegistryEntry> ParseRegCommands(string filePath)
        {
            var entries = new List<RegistryEntry>();
            var lines = File.ReadAllLines(filePath);
            string currentCategory = "General";
            string currentComment = null;

            var patterns = new[]
            {
                @"reg\s+add\s+""([^""]+)""\s+/v\s+""([^""]+)""\s+/t\s+(\S+)",
                @"reg\s+add\s+""([^""]+)""\s+/v\s+(\S+)\s+/t\s+(\S+)",
                @"Reg\.exe\s+add\s+""([^""]+)""\s+/v\s+""([^""]+)""\s+/t\s+(\S+)",
                @"Reg\.exe\s+add\s+""([^""]+)""\s+/v\s+(\S+)\s+/t\s+(\S+)"
            };

            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    currentComment = null;
                    continue;
                }

                var trimmed = line.Trim();

                if (trimmed.StartsWith("//"))
                {
                    currentComment = trimmed.Substring(2).Trim();
                    continue;
                }

                if (trimmed.StartsWith("#") || trimmed.StartsWith("::"))
                {
                    currentComment = trimmed.Substring(trimmed.StartsWith("::") ? 2 : 1).Trim();
                    continue;
                }

                if (trimmed.StartsWith("[") && trimmed.EndsWith("]"))
                {
                    currentCategory = trimmed.Trim('[', ']');
                    currentComment = null;
                    continue;
                }

                Match match = null;
                foreach (var pattern in patterns)
                {
                    match = Regex.Match(trimmed, pattern, RegexOptions.IgnoreCase);
                    if (match.Success)
                        break;
                }

                if (match != null && match.Success)
                {
                    var path = match.Groups[1].Value;
                    var valueName = match.Groups[2].Value.Trim('"');
                    var type = match.Groups[3].Value.ToUpper();

                    entries.Add(new RegistryEntry
                    {
                        Path = path,
                        ValueName = valueName,
                        Type = type,
                        Category = currentCategory,
                        Comment = currentComment
                    });

                    currentComment = null;
                }
            }

            return entries;
        }

        static List<RegistryEntry> ParsePowerCfgNetshCommands(string filePath)
        {
            var entries = new List<RegistryEntry>();
            var lines = File.ReadAllLines(filePath);
            string currentCategory = "Power & Network Settings";
            string currentComment = null;

            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    currentComment = null;
                    continue;
                }

                var trimmed = line.Trim();

                if (trimmed.StartsWith("//") || trimmed.StartsWith("#") || trimmed.StartsWith("::"))
                {
                    currentComment = trimmed.TrimStart('/', '#', ':').Trim();
                    continue;
                }

                if (trimmed.StartsWith("[") && trimmed.EndsWith("]"))
                {
                    currentCategory = trimmed.Trim('[', ']');
                    currentComment = null;
                    continue;
                }

                if (trimmed.StartsWith("powercfg", StringComparison.OrdinalIgnoreCase))
                {
                    ParsePowerCfgCommand(trimmed, currentCategory, currentComment, entries);
                    currentComment = null;
                }
                else if (trimmed.StartsWith("netsh", StringComparison.OrdinalIgnoreCase))
                {
                    ParseNetshCommand(trimmed, currentCategory, currentComment, entries);
                    currentComment = null;
                }
            }

            return entries;
        }

        static void ParsePowerCfgCommand(string command, string category, string comment, List<RegistryEntry> entries)
        {
            var setacMatch = Regex.Match(command, @"powercfg\s+-setacvalueindex\s+\S+\s+(\S+)\s+(\S+)", RegexOptions.IgnoreCase);
            if (setacMatch.Success)
            {
                var subgroup = setacMatch.Groups[1].Value;
                var setting = setacMatch.Groups[2].Value;

                entries.Add(new RegistryEntry
                {
                    Path = $"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power\\User\\PowerSchemes\\{{ActiveScheme}}\\{MapPowerSubgroup(subgroup)}",
                    ValueName = MapPowerSetting(setting),
                    Type = "REG_DWORD",
                    Category = category,
                    Comment = comment
                });
            }

            if (command.Contains("/h off", StringComparison.OrdinalIgnoreCase))
            {
                entries.Add(new RegistryEntry
                {
                    Path = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power",
                    ValueName = "HibernateEnabled",
                    Type = "REG_DWORD",
                    Category = category,
                    Comment = comment
                });
            }

            var standbyMatch = Regex.Match(command, @"-change\s+-standby-timeout-ac\s+(\d+)", RegexOptions.IgnoreCase);
            if (standbyMatch.Success)
            {
                entries.Add(new RegistryEntry
                {
                    Path = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings",
                    ValueName = "ACStandbyTimeout",
                    Type = "REG_DWORD",
                    Category = category,
                    Comment = comment
                });
            }
        }

        static void ParseNetshCommand(string command, string category, string comment, List<RegistryEntry> entries)
        {
            if (command.Contains("autotuninglevel", StringComparison.OrdinalIgnoreCase))
            {
                entries.Add(new RegistryEntry
                {
                    Path = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                    ValueName = "EnableWsd",
                    Type = "REG_DWORD",
                    Category = category,
                    Comment = comment
                });
            }

            if (command.Contains("chimney", StringComparison.OrdinalIgnoreCase))
            {
                entries.Add(new RegistryEntry
                {
                    Path = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                    ValueName = "EnableTCPChimney",
                    Type = "REG_DWORD",
                    Category = category,
                    Comment = comment
                });
            }

            if (command.Contains("rsc=", StringComparison.OrdinalIgnoreCase))
            {
                entries.Add(new RegistryEntry
                {
                    Path = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                    ValueName = "EnableRSC",
                    Type = "REG_DWORD",
                    Category = category,
                    Comment = comment
                });
            }

            if (command.Contains("timestamps", StringComparison.OrdinalIgnoreCase))
            {
                entries.Add(new RegistryEntry
                {
                    Path = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                    ValueName = "Tcp1323Opts",
                    Type = "REG_DWORD",
                    Category = category,
                    Comment = comment
                });
            }

            if (command.Contains("ipv6") && command.Contains("disabled", StringComparison.OrdinalIgnoreCase))
            {
                entries.Add(new RegistryEntry
                {
                    Path = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\TCPIP6\\Parameters",
                    ValueName = "DisabledComponents",
                    Type = "REG_DWORD",
                    Category = category,
                    Comment = comment
                });
            }
        }

        static string MapPowerSubgroup(string subgroup)
        {
            return subgroup.ToLower() switch
            {
                "sub_processor" => "54533251-82be-4824-96c1-47b60b740d00",
                "sub_sleep" => "238c9fa8-0aad-41ed-83f4-97be242c8f20",
                "sub_disk" => "0012ee47-9041-4b5d-9b77-535fba8b1442",
                "sub_video" => "7516b95f-f776-4464-8c53-06167f40cc99",
                _ => subgroup
            };
        }

        static string MapPowerSetting(string setting)
        {
            return setting.ToUpper() switch
            {
                "PROCTHROTTLEMIN" => "ACSettingIndex",
                "PROCTHROTTLEMAX" => "ACSettingIndex",
                "PERFEPP" => "ACSettingIndex",
                _ => setting
            };
        }

        static List<RegistryEntry> ParseJsonConfig(string filePath)
        {
            var entries = new List<RegistryEntry>();

            try
            {
                string json = File.ReadAllText(filePath);
                var lines = json.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                string currentPath = null;
                string currentValue = null;
                string currentType = null;
                string currentCategory = null;

                foreach (var line in lines)
                {
                    var trimmed = line.Trim().TrimEnd(',');

                    if (trimmed.Contains("\"category\""))
                    {
                        currentCategory = ExtractJsonValue(trimmed);
                    }
                    else if (trimmed.Contains("\"path\""))
                    {
                        currentPath = ExtractJsonValue(trimmed);
                    }
                    else if (trimmed.Contains("\"value\""))
                    {
                        currentValue = ExtractJsonValue(trimmed);
                    }
                    else if (trimmed.Contains("\"type\""))
                    {
                        currentType = ExtractJsonValue(trimmed);

                        if (!string.IsNullOrEmpty(currentPath) && !string.IsNullOrEmpty(currentValue))
                        {
                            entries.Add(new RegistryEntry
                            {
                                Path = currentPath,
                                ValueName = currentValue,
                                Type = currentType ?? "REG_DWORD",
                                Category = currentCategory
                            });

                            currentPath = null;
                            currentValue = null;
                            currentType = null;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error parsing JSON: {ex.Message}");
            }

            return entries;
        }

        static List<RegistryEntry> ParseTextConfig(string filePath)
        {
            var entries = new List<RegistryEntry>();
            var lines = File.ReadAllLines(filePath);
            string currentCategory = "General";

            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line) || line.TrimStart().StartsWith("//") || line.TrimStart().StartsWith("#"))
                    continue;

                if (line.StartsWith("[") && line.EndsWith("]"))
                {
                    currentCategory = line.Trim('[', ']');
                    continue;
                }

                var parts = line.Split('|');
                if (parts.Length >= 2)
                {
                    var path = parts[0].Trim();
                    var valueName = parts[1].Trim();
                    var type = parts.Length >= 3 ? parts[2].Trim() : "REG_DWORD";

                    entries.Add(new RegistryEntry
                    {
                        Path = path,
                        ValueName = valueName,
                        Type = type,
                        Category = currentCategory
                    });
                }
            }

            return entries;
        }

        static string ExtractJsonValue(string line)
        {
            var match = Regex.Match(line, @"""[^""]+"":\s*""([^""]*)""");
            return match.Success ? match.Groups[1].Value : null;
        }

        static RegistryBackup BackupRegistryValue(RegistryEntry entry)
        {
            var backup = new RegistryBackup
            {
                Entry = entry,
                Success = false,
                Timestamp = DateTime.Now
            };

            try
            {
                var (hive, subKey) = ParseRegistryPath(entry.Path);
                if (hive == null)
                {
                    backup.ErrorMessage = "Invalid registry hive";
                    return backup;
                }

                using (var key = hive.OpenSubKey(subKey, false))
                {
                    if (key == null)
                    {
                        backup.ErrorMessage = "Key does not exist";
                        backup.ValueExists = false;
                        return backup;
                    }

                    var valueNames = key.GetValueNames();
                    if (!valueNames.Contains(entry.ValueName))
                    {
                        backup.ErrorMessage = "Value does not exist";
                        backup.ValueExists = false;
                        return backup;
                    }

                    backup.OriginalValue = key.GetValue(entry.ValueName);
                    backup.OriginalValueKind = key.GetValueKind(entry.ValueName);
                    backup.ValueExists = true;
                    backup.Success = true;
                }
            }
            catch (Exception ex)
            {
                backup.ErrorMessage = ex.Message;
            }

            return backup;
        }

        static (RegistryKey hive, string subKey) ParseRegistryPath(string path)
        {
            var parts = path.Split(new[] { '\\' }, 2);
            if (parts.Length < 2)
                return (null, null);

            RegistryKey hive = parts[0].ToUpper() switch
            {
                "HKEY_LOCAL_MACHINE" or "HKLM" => Registry.LocalMachine,
                "HKEY_CURRENT_USER" or "HKCU" => Registry.CurrentUser,
                "HKEY_CLASSES_ROOT" or "HKCR" => Registry.ClassesRoot,
                "HKEY_USERS" or "HKU" => Registry.Users,
                "HKEY_CURRENT_CONFIG" or "HKCC" => Registry.CurrentConfig,
                _ => null
            };

            return (hive, parts[1]);
        }

        static void SaveBackupData(List<RegistryBackup> backups, string outputFile)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Registry Backup Data");
            sb.AppendLine($"Generated: {DateTime.Now}");
            sb.AppendLine("=".PadRight(80, '='));
            sb.AppendLine();

            foreach (var backup in backups)
            {
                sb.AppendLine($"Path: {backup.Entry.Path}");
                sb.AppendLine($"Value Name: {backup.Entry.ValueName}");
                sb.AppendLine($"Expected Type: {backup.Entry.Type}");
                sb.AppendLine($"Value Exists: {backup.ValueExists}");

                if (backup.Success)
                {
                    sb.AppendLine($"Original Value Kind: {backup.OriginalValueKind}");
                    sb.AppendLine($"Original Value: {FormatValue(backup.OriginalValue, backup.OriginalValueKind)}");
                }
                else
                {
                    sb.AppendLine($"Error: {backup.ErrorMessage}");
                }

                sb.AppendLine("-".PadRight(80, '-'));
                sb.AppendLine();
            }

            File.WriteAllText(outputFile, sb.ToString());
        }

        static void SaveBackupDataJson(List<RegistryBackup> backups, string outputFile)
        {
            var sb = new StringBuilder();
            sb.AppendLine("{");
            sb.AppendLine($"  \"generatedDate\": \"{DateTime.Now:yyyy-MM-dd HH:mm:ss}\",");
            sb.AppendLine("  \"backups\": [");

            for (int i = 0; i < backups.Count; i++)
            {
                var backup = backups[i];
                sb.AppendLine("    {");
                sb.AppendLine($"      \"category\": \"{EscapeJson(backup.Entry.Category)}\",");
                sb.AppendLine($"      \"path\": \"{EscapeJson(backup.Entry.Path)}\",");
                sb.AppendLine($"      \"valueName\": \"{EscapeJson(backup.Entry.ValueName)}\",");
                sb.AppendLine($"      \"expectedType\": \"{backup.Entry.Type}\",");
                sb.AppendLine($"      \"valueExists\": {backup.ValueExists.ToString().ToLower()},");

                if (backup.Success)
                {
                    sb.AppendLine($"      \"actualType\": \"{backup.OriginalValueKind}\",");
                    sb.AppendLine($"      \"originalValue\": \"{EscapeJson(FormatValue(backup.OriginalValue, backup.OriginalValueKind))}\",");
                    sb.AppendLine($"      \"success\": true");
                }
                else
                {
                    sb.AppendLine($"      \"error\": \"{EscapeJson(backup.ErrorMessage)}\",");
                    sb.AppendLine($"      \"success\": false");
                }

                sb.Append("    }");
                if (i < backups.Count - 1)
                    sb.AppendLine(",");
                else
                    sb.AppendLine();
            }

            sb.AppendLine("  ]");
            sb.AppendLine("}");

            File.WriteAllText(outputFile, sb.ToString());
        }

        static string EscapeJson(string value)
        {
            if (string.IsNullOrEmpty(value))
                return value;

            return value
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\n", "\\n")
                .Replace("\r", "\\r")
                .Replace("\t", "\\t");
        }

        static void GenerateRevertScript(List<RegistryBackup> backups, string scriptFile)
        {
            var sb = new StringBuilder();
            sb.AppendLine("@echo off");
            sb.AppendLine(":: Registry Revert Script");
            sb.AppendLine($":: Generated: {DateTime.Now}");
            sb.AppendLine(":: Run as Administrator");
            sb.AppendLine();
            sb.AppendLine("echo Reverting registry changes...");
            sb.AppendLine();

            foreach (var backup in backups.Where(b => b.Success && b.ValueExists))
            {
                var regType = ConvertToRegType(backup.OriginalValueKind);
                var value = FormatValueForBatch(backup.OriginalValue, backup.OriginalValueKind);

                sb.AppendLine($"reg add \"{backup.Entry.Path}\" /v \"{backup.Entry.ValueName}\" /t {regType} /d {value} /f");
            }

            foreach (var backup in backups.Where(b => !b.ValueExists))
            {
                sb.AppendLine($"reg delete \"{backup.Entry.Path}\" /v \"{backup.Entry.ValueName}\" /f 2>nul");
            }

            sb.AppendLine();
            sb.AppendLine("echo Revert complete!");
            sb.AppendLine("pause");

            File.WriteAllText(scriptFile, sb.ToString());
        }

        static void GenerateDefaultValuesFile(List<RegistryBackup> backups, string outputFile)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"# Default Registry Values");
            sb.AppendLine($"# Generated: {DateTime.Now}");
            sb.AppendLine();

            string currentCategory = null;

            foreach (var backup in backups)
            {
                if (backup.Entry.Category != currentCategory)
                {
                    currentCategory = backup.Entry.Category;
                    sb.AppendLine();
                    sb.AppendLine($"[{currentCategory}]");
                }

                if (backup.Success && backup.ValueExists)
                {
                    var regType = ConvertToRegType(backup.OriginalValueKind);
                    var value = FormatValueForRegAdd(backup.OriginalValue, backup.OriginalValueKind);

                    sb.AppendLine($"reg add \"{backup.Entry.Path}\" /v \"{backup.Entry.ValueName}\" /t {regType} /d {value} /f");
                }
                else
                {
                    sb.AppendLine($"reg delete \"{backup.Entry.Path}\" /v \"{backup.Entry.ValueName}\" /f");
                }
            }

            File.WriteAllText(outputFile, sb.ToString());
        }

        static string FormatValueForRegAdd(object value, RegistryValueKind kind)
        {
            if (value == null)
                return "\"\"";

            switch (kind)
            {
                case RegistryValueKind.Binary:
                    return BitConverter.ToString((byte[])value).Replace("-", "");

                case RegistryValueKind.DWord:
                case RegistryValueKind.QWord:
                    long numValue = Convert.ToInt64(value);
                    return numValue.ToString();

                case RegistryValueKind.MultiString:
                    var multiStr = (string[])value;
                    return $"\"{string.Join("\\0", multiStr)}\"";

                case RegistryValueKind.String:
                case RegistryValueKind.ExpandString:
                default:
                    string strValue = value.ToString();
                    strValue = strValue.Replace("\\", "\\\\");
                    return $"\"{strValue}\"";
            }
        }

        static string ConvertToRegType(RegistryValueKind kind)
        {
            return kind switch
            {
                RegistryValueKind.String => "REG_SZ",
                RegistryValueKind.DWord => "REG_DWORD",
                RegistryValueKind.QWord => "REG_QWORD",
                RegistryValueKind.Binary => "REG_BINARY",
                RegistryValueKind.MultiString => "REG_MULTI_SZ",
                RegistryValueKind.ExpandString => "REG_EXPAND_SZ",
                _ => "REG_SZ"
            };
        }

        static string FormatValue(object value, RegistryValueKind kind)
        {
            if (value == null)
                return "(null)";

            return kind switch
            {
                RegistryValueKind.Binary => BitConverter.ToString((byte[])value).Replace("-", ""),
                RegistryValueKind.MultiString => string.Join("\\0", (string[])value),
                _ => value.ToString()
            };
        }

        static string FormatValueForBatch(object value, RegistryValueKind kind)
        {
            if (value == null)
                return "\"\"";

            return kind switch
            {
                RegistryValueKind.Binary => BitConverter.ToString((byte[])value).Replace("-", ""),
                RegistryValueKind.DWord or RegistryValueKind.QWord => value.ToString(),
                RegistryValueKind.MultiString => $"\"{string.Join("\\0", (string[])value)}\"",
                _ => $"\"{value}\""
            };
        }
    }

    class RegistryEntry
    {
        public string Path { get; set; }
        public string ValueName { get; set; }
        public string Type { get; set; }
        public string Category { get; set; }
        public string Comment { get; set; }
    }

    class RegistryBackup
    {
        public RegistryEntry Entry { get; set; }
        public bool Success { get; set; }
        public bool ValueExists { get; set; }
        public object OriginalValue { get; set; }
        public RegistryValueKind OriginalValueKind { get; set; }
        public string ErrorMessage { get; set; }
        public DateTime Timestamp { get; set; }
    }
}