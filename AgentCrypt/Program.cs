/*
 * Copyright (c) 2019-2022, Nicola Di Lieto <nicola.dilieto@gmail.com>
 * Copyright (c) 2025, Ported to C#/.NET by GitHub Copilot
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

using System.Text;
using LibAgentCrypt;

class Program
{
    static int Main(string[] args)
    {
        bool toStdout = false;
        bool decrypt = false;
        bool force = false;
        bool keep = false;
        bool text = false;
        bool verbose = false;
        string? keyFingerprint = null;
        var files = new List<string>();

        // Parse arguments
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-c":
                    toStdout = true;
                    break;
                case "-d":
                    decrypt = true;
                    break;
                case "-e":
                    if (i + 1 >= args.Length)
                    {
                        Console.Error.WriteLine("Error: -e requires a fingerprint argument");
                        return 1;
                    }
                    keyFingerprint = args[++i];
                    break;
                case "-f":
                    force = true;
                    break;
                case "-k":
                    keep = true;
                    break;
                case "-t":
                    text = true;
                    break;
                case "-v":
                    verbose = true;
                    break;
                case "-V":
                    Console.WriteLine($"agentcrypt {AgentCrypt.GetVersion()} (.NET port)");
                    Console.WriteLine("Copyright (C) 2019-2022 Nicola Di Lieto");
                    Console.WriteLine("Copyright (C) 2025 GitHub Copilot (.NET port)");
                    Console.WriteLine("You may redistribute this program under the terms of the ISC license.");
                    return 0;
                case "-h":
                case "--help":
                    PrintUsage();
                    return 0;
                default:
                    if (args[i].StartsWith("-"))
                    {
                        Console.Error.WriteLine($"Error: Unknown option {args[i]}");
                        PrintUsage();
                        return 1;
                    }
                    files.Add(args[i]);
                    break;
            }
        }

        // Validate options
        if (keyFingerprint != null && decrypt)
        {
            Console.Error.WriteLine("Error: specify either -e or -d, not both");
            return 1;
        }

        // Check SSH_AUTH_SOCK
        var agentPath = Environment.GetEnvironmentVariable("SSH_AUTH_SOCK");
        if (string.IsNullOrEmpty(agentPath))
        {
            Console.Error.WriteLine("Error: SSH_AUTH_SOCK environment variable not set");
            return 1;
        }

        try
        {
            if (files.Count == 0)
            {
                // Process stdin/stdout
                if (keep)
                {
                    Console.Error.WriteLine("Warning: -k is redundant when reading from stdin");
                }
                if (toStdout)
                {
                    Console.Error.WriteLine("Warning: -c is redundant when reading from stdin");
                }

                return ProcessStream(Console.OpenStandardInput(), Console.OpenStandardOutput(),
                    keyFingerprint, decrypt, text, verbose, agentPath);
            }
            else
            {
                // Process files
                if (keep && toStdout)
                {
                    Console.Error.WriteLine("Warning: -k is redundant with -c");
                }

                foreach (var file in files)
                {
                    if (ProcessFile(file, keyFingerprint, decrypt, text, keep, toStdout, force, verbose, agentPath) != 0)
                    {
                        return 1;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }

        return 0;
    }

    static void PrintUsage()
    {
        Console.WriteLine("Usage: agentcrypt [OPTION]... [FILE]...");
        Console.WriteLine("Encrypt/decrypt FILEs with ssh-agent (by default, encrypt in-place).");
        Console.WriteLine();
        Console.WriteLine("  -c    write on stdout, keep input files unchanged");
        Console.WriteLine("  -d    decrypt");
        Console.WriteLine("  -e FP encrypt using a ssh key with the specified SHA256 fingerprint");
        Console.WriteLine("        Use 'ssh-add -l -E sha256' to display available fingerprints");
        Console.WriteLine("  -f    force overwrite of output files");
        Console.WriteLine("  -h    give this help");
        Console.WriteLine("  -k    keep (don't delete) input files");
        Console.WriteLine("  -t    encrypt/decrypt line by line, output text");
        Console.WriteLine("  -v    verbose mode");
        Console.WriteLine("  -V    display version number");
        Console.WriteLine();
        Console.WriteLine("With no FILE, read standard input.");
        Console.WriteLine();
        Console.WriteLine("Report bugs at https://github.com/ndilieto/libagentcrypt/issues");
    }

    static int ProcessFile(string inputFile, string? keyFingerprint, bool decrypt, bool text,
        bool keep, bool toStdout, bool force, bool verbose, string agentPath)
    {
        try
        {
            if (!File.Exists(inputFile))
            {
                Console.Error.WriteLine($"Error: File '{inputFile}' not found");
                return 1;
            }

            var ext = text ? ".act" : ".acb";
            var hasExt = inputFile.EndsWith(ext, StringComparison.OrdinalIgnoreCase);

            if (decrypt && !hasExt)
            {
                Console.Error.WriteLine($"Warning: {inputFile}: suffix is not {ext} - ignored");
                return 0;
            }

            if (!decrypt && hasExt)
            {
                Console.Error.WriteLine($"Warning: {inputFile} already has {ext} suffix - ignored");
                return 0;
            }

            string outputFile;
            if (toStdout)
            {
                outputFile = "-";
            }
            else if (decrypt)
            {
                outputFile = inputFile.Substring(0, inputFile.Length - ext.Length);
            }
            else
            {
                outputFile = inputFile + ext;
            }

            if (outputFile != "-" && File.Exists(outputFile) && !force)
            {
                Console.Write($"{outputFile} already exists; do you wish to overwrite (y or n)? ");
                var response = Console.ReadLine();
                if (string.IsNullOrEmpty(response) || !response.StartsWith("y", StringComparison.OrdinalIgnoreCase))
                {
                    return 0;
                }
            }

            if (text)
            {
                ProcessTextFile(inputFile, outputFile, keyFingerprint, decrypt, verbose, agentPath);
            }
            else
            {
                if (verbose)
                {
                    Console.Error.WriteLine($"{(decrypt ? "Decrypting" : "Encrypting")} {inputFile} to {outputFile} in binary mode");
                }

                if (toStdout)
                {
                    using var input = File.OpenRead(inputFile);
                    using var output = Console.OpenStandardOutput();
                    if (decrypt)
                    {
                        AgentCrypt.DecryptStream(input, output, agentPath);
                    }
                    else
                    {
                        AgentCrypt.EncryptStream(input, output, keyFingerprint, agentPath);
                    }
                }
                else
                {
                    if (decrypt)
                    {
                        AgentCrypt.DecryptFile(inputFile, outputFile, agentPath);
                    }
                    else
                    {
                        AgentCrypt.EncryptFile(inputFile, outputFile, keyFingerprint, agentPath);
                    }

                    if (!keep)
                    {
                        if (verbose)
                        {
                            Console.Error.WriteLine($"Removing {inputFile}");
                        }
                        File.Delete(inputFile);
                    }

                    // Copy file metadata
                    var fileInfo = new FileInfo(inputFile);
                    if (fileInfo.Exists)
                    {
                        var outputInfo = new FileInfo(outputFile);
                        outputInfo.CreationTime = fileInfo.CreationTime;
                        outputInfo.LastWriteTime = fileInfo.LastWriteTime;
                        outputInfo.LastAccessTime = fileInfo.LastAccessTime;
                    }
                }
            }

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error processing {inputFile}: {ex.Message}");
            return 1;
        }
    }

    static void ProcessTextFile(string inputFile, string outputFile, string? keyFingerprint,
        bool decrypt, bool verbose, string agentPath)
    {
        if (verbose)
        {
            Console.Error.WriteLine($"{(decrypt ? "Decrypting" : "Encrypting")} {inputFile} to {outputFile} in text mode");
        }

        using var input = File.OpenText(inputFile);
        using var output = outputFile == "-" ? Console.Out : new StreamWriter(outputFile);

        string? line;
        while ((line = input.ReadLine()) != null)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                output.WriteLine();
                continue;
            }

            if (decrypt)
            {
                var encrypted = AgentCrypt.FromBase64(line);
                var decrypted = AgentCrypt.Decrypt(encrypted, agentPath);
                output.WriteLine(Encoding.UTF8.GetString(decrypted));
            }
            else
            {
                var cleartext = Encoding.UTF8.GetBytes(line);
                var encrypted = AgentCrypt.Encrypt(cleartext, keyFingerprint, 0, agentPath);
                output.WriteLine(AgentCrypt.ToBase64(encrypted));
            }
        }
    }

    static int ProcessStream(Stream input, Stream output, string? keyFingerprint,
        bool decrypt, bool text, bool verbose, string agentPath)
    {
        try
        {
            if (text)
            {
                using var reader = new StreamReader(input);
                using var writer = new StreamWriter(output);

                string? line;
                while ((line = reader.ReadLine()) != null)
                {
                    if (string.IsNullOrWhiteSpace(line))
                    {
                        writer.WriteLine();
                        continue;
                    }

                    if (decrypt)
                    {
                        var encrypted = AgentCrypt.FromBase64(line);
                        var decrypted = AgentCrypt.Decrypt(encrypted, agentPath);
                        writer.WriteLine(Encoding.UTF8.GetString(decrypted));
                    }
                    else
                    {
                        var cleartext = Encoding.UTF8.GetBytes(line);
                        var encrypted = AgentCrypt.Encrypt(cleartext, keyFingerprint, 0, agentPath);
                        writer.WriteLine(AgentCrypt.ToBase64(encrypted));
                    }
                }
            }
            else
            {
                if (decrypt)
                {
                    AgentCrypt.DecryptStream(input, output, agentPath);
                }
                else
                {
                    AgentCrypt.EncryptStream(input, output, keyFingerprint, agentPath);
                }
            }

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }
    }
}
