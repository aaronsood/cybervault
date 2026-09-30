using System;
using System.IO;
using System.Collections.Generic;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Threading;
using System.Runtime.CompilerServices;

public class PasswordEntry
{
    public string Title { get;set; } = "";
    public string Username { get;set; } = "";
    public string Password { get;set; } = "";
    public string URL { get;set; } = "";
    public DateTime CreatedAt { get;set; } = DateTime.Now;
}

class Program
{
    private const string VaultPath = "vault.dat";
    private static byte[] key = Array.Empty<byte>();
    private static byte[] vaultSalt = Array.Empty<byte>();
    private static List<PasswordEntry> vault = new();

    private const int Iterations = 600_000;

    static byte[] GenerateSalt()
    {
        return RandomNumberGenerator.GetBytes(16);
    }

    static bool VerifyMasterPassword(string password)
    {
        string stored;

        try
        {
            stored = File.ReadAllText("master.txt");
        }

        catch (IOException)
        {
            Console.WriteLine("Could not read the master password file.");
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            Console.WriteLine("Access denied to master password file.");
            return false;
        }
        
        string[] parts = stored.Split(':');

        if(parts.Length !=2) return false;


        byte[] salt;
        byte[] storedHash;

        try
        {
            salt = Convert.FromBase64String(parts[0]);
            storedHash = Convert.FromBase64String(parts[1]);
        }

        catch (FormatException)
        {
            return false;
        }

        if (salt.Length != 16 || storedHash.Length != 32)
            return false;

            
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            Iterations,
            HashAlgorithmName.SHA256,
            32
        );

        return CryptographicOperations.FixedTimeEquals(hash, storedHash);
    }

    static byte[] DeriveKey(string password, byte[] salt)
    {
        return Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            Iterations,
            HashAlgorithmName.SHA256,
            32
        );
    }
    static void Main(string[] args)
    {
        if (!File.Exists("master.txt"))
        {
            SetupMasterPassword();
        }
        
        int attempts = 0;
        bool authenticated = false;

        while (attempts < 3 && !authenticated)
        {
            Console.Write("Enter master password: ");
            string EnteredPassword = ReadPassword();

            if (VerifyMasterPassword(EnteredPassword))
            {
                vault = LoadVault(EnteredPassword);
                authenticated = true;
            }
            else
            {
                attempts++;
                Console.WriteLine($"Incorrect master password ({attempts}/3)");
                Thread.Sleep(1000);
            }
        }
        if (!authenticated) return;

        bool running = true;
        
        while (running)
        {
            Console.Clear();
            Console.WriteLine("1. View Passwords");
            Console.WriteLine("2. Add Entry");
            Console.WriteLine("3. Delete Entry");
            Console.WriteLine("4. Search Entries");
            Console.WriteLine("5. Edit Entries");
            Console.WriteLine("6. Generate Password");
            Console.WriteLine("7. Exit");
            Console.Write("\nSelect an option: ");

            string? selection = Console.ReadLine();

            switch(selection)
            {
                case "1":
                    ViewPasswords();
                    break;
                case "2":
                    AddEntry();
                    break;
                case "3":
                    DeleteEntry();
                        break;
                case "4":
                    SearchEntries();
                    break;
                case "5":
                    EditEntry();
                    break;
                case "6":
                    Console.Clear();
                    Console.WriteLine("Generated Password: " + GeneratePassword());
                    Console.WriteLine("\nPress any key to return to menu.");
                    Console.ReadKey();
                    break;
                case "7":
                    Console.WriteLine("\nAdios!");
                    running = false;
                    break;
                default:
                    Console.WriteLine("\nInvalid option try again broski");
                    Console.ReadKey();
                    break;
            }
        }

        if (key.Length > 0)
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    static string ReadPassword()
    {
        StringBuilder password = new StringBuilder();

        while(true)
        {
            ConsoleKeyInfo keyInfo = Console.ReadKey(true);

            if (keyInfo.Key == ConsoleKey.Enter)
            break;

            if (keyInfo.Key == ConsoleKey.Backspace && password.Length > 0)
            {
                password.Length--;
                Console.Write("\b \b");
            }
            else if (!char.IsControl(keyInfo.KeyChar))
            {
                password.Append(keyInfo.KeyChar);
                Console.Write("*");
            }
        }
        Console.WriteLine();
        return password.ToString();
    }
    static void SetupMasterPassword()
    {
        string masterPassword;
        while (true)
        {
            Console.Write("Create a master password: ");
            masterPassword = ReadPassword();

            if (masterPassword.Length < 8)
            {
                Console.WriteLine("Must be at least 8 characters");
                continue;
            }

            Console.Write("Confirm master password: ");
            if (ReadPassword() == masterPassword) break;

            Console.WriteLine("Passwords don't match, try again crodie");
        }

        byte[] salt = GenerateSalt();

        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
            masterPassword,
            salt,
            Iterations,
            HashAlgorithmName.SHA256,
            32
        );
        

        File.WriteAllText("master.txt",
            Convert.ToBase64String(salt) + ":" +
            Convert.ToBase64String(hash));

        Console.WriteLine("Master Password created.");

        Console.WriteLine("Press any key to log in");

        Console.ReadKey();
    }

    private static List<PasswordEntry> LoadVault(string masterPassword)
    {
        if (!File.Exists(VaultPath))
        {
            vaultSalt = GenerateSalt();
            key = DeriveKey(masterPassword, vaultSalt);
            return new List<PasswordEntry>();
        }

        byte[] data = File.ReadAllBytes(VaultPath);

        if (data.Length < 44)
        {
            Console.WriteLine("Vault file is corrupted");
            Console.ReadKey();
            Environment.Exit(1);
        }

        vaultSalt = data[..16];
        byte[] nonce = data[16..28];
        byte[] tag = data[28..44];
        byte[] cipher = data[44..];

        key = DeriveKey(masterPassword, vaultSalt) ; 
        byte[] plain = new byte[cipher.Length];
        
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(nonce, cipher, tag, plain);
        }

        catch (CryptographicException)
        {
           Console.WriteLine("Could not decrypt vault, most likely corrupted (or tampered with)");
           Console.ReadKey();
           Environment.Exit(1);
        }
        var entries = JsonSerializer.Deserialize<List<PasswordEntry>>(plain)?? new List<PasswordEntry>();
        CryptographicOperations.ZeroMemory(plain);
        return entries;
    }
    
    private static void SaveVault()
    {
        byte[] plain = JsonSerializer.SerializeToUtf8Bytes(vault);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] cipher = new byte[plain.Length];
        byte[] tag = new byte[16];

        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plain, cipher, tag);

        string tempPath = VaultPath + ".tmp";
        File.WriteAllBytes(tempPath,
        vaultSalt.Concat(nonce).Concat(tag).Concat(cipher).ToArray());
        File.Move(tempPath, VaultPath, overwrite: true);

        CryptographicOperations.ZeroMemory(plain);
    }
    private static void AddEntry()
    {
        Console.Clear();
        Console.WriteLine("ADD NEW ENTRY");
        
        Console.Write("Title/Service Name: ");
        string title = Console.ReadLine() ?? "";
    
        Console.Write("Username / Email: ");
        string username = Console.ReadLine() ?? "";

        Console.Write("Password: ");
        string password = ReadPassword();

        Console.Write("URL (Optional): ");
        string url = Console.ReadLine() ?? "";

        var entry = new PasswordEntry
        {
            Title = title,
            Username = username,
            Password = password,
            URL = url,
            CreatedAt = DateTime.Now
        };
        
        vault.Add(entry);
        SaveVault();

        Console.WriteLine("\nEntry added and saved.");
            Console.WriteLine("Press any key to return to menu");
            Console.ReadKey();

    }
    
    private static void ViewPasswords()
    {
        Console.Clear();
        Console.WriteLine("Saved Passwords\n");
        
        if (vault.Count == 0)
        {
            Console.WriteLine("No entries yet.");
        }
        else
        {
            for (int i=0; i < vault.Count; i++)
            {
                var entry = vault[i];
                Console.WriteLine($"{i+1}. {entry.Title}");
                Console.WriteLine($"    Username: {entry.Username}");
                Console.WriteLine($"    Password: {new string('*', entry.Password.Length)}");
                Console.WriteLine($"    URL: {entry.URL}");
                Console.WriteLine();
            }

            Console.Write("\nEnter an entry number to reveal its password (or press enter to go back): ");
            string? pick = Console.ReadLine();
            if(int.TryParse(pick, out int n) && n >= 1 && n <= vault.Count)
            {
                Console.WriteLine($"\n{vault[n - 1].Title}: {vault[n-1].Password}");
                Console.WriteLine("Press any key to hide");
                Console.ReadKey();
                Console.Clear();
                return;
            }
        }
        Console.WriteLine("\nPress any key to return to menu");
        Console.ReadKey();
    }

    private static void SearchEntries()
    {
        Console.Clear();
        Console.Write("Search by service name: ");
        string query = Console.ReadLine() ?? "";

        var results = vault.FindAll(entry =>
        entry.Title.Contains(query, StringComparison.OrdinalIgnoreCase));

        Console.WriteLine("\nSearch Results:\n");

        if (results.Count == 0)
        {
            Console.WriteLine("No matching entries found");
        }
        else
        {
            foreach (var entry in results)
            {
                Console.WriteLine($"Title: {entry.Title}");
                
                Console.WriteLine($"Username: {entry.Username}");
                
                Console.WriteLine($"URL: {entry.URL}");

                Console.WriteLine();
            }
        }
        Console.WriteLine("Press any key to return to menu");
        Console.ReadKey();
    }
    

    private static void EditEntry()
    {
        Console.Clear();
        Console.WriteLine("Edit Entry\n");

        if (vault.Count == 0)
        {
            Console.WriteLine("No entries to edit");
            Console.ReadKey();
            return;
        }
        for (int i = 0; i < vault.Count; i++)
        {
            Console.WriteLine($"{i + 1}. {vault[i].Title}");
        }
        Console.Write("\nEnter the number of the entry to edit: ");
        string? input = Console.ReadLine();

        if (!int.TryParse(input, out int number) || 
            number < 1 || 
            number > vault.Count)
        {
            Console.WriteLine("Invalid entry number");
            Console.ReadKey();
            return;
        }
        var entry = vault[number - 1];

        Console.Write($"New title ({entry.Title}): ");
        string title = Console.ReadLine() ?? "";

        Console.Write($"New username/email ({entry.Username}): ");
        string username = Console.ReadLine() ?? "";

        Console.Write("New password (leave blank to keep current):  ");
        string password = ReadPassword();

        Console.Write($"New URL ({entry.URL}): ");
        string url = Console.ReadLine() ?? "";

        if (!string.IsNullOrWhiteSpace(title))
            entry.Title = title;
            
        if (!string.IsNullOrWhiteSpace(username))
            entry.Username = username;

        if (!string.IsNullOrEmpty(password))
            entry.Password = password;

            entry.URL = url;

        
        SaveVault();

        Console.WriteLine("\nEntry updated successfully");
        Console.ReadKey();
            
    }

    private static void DeleteEntry()
    {
        Console.Clear();
        Console.WriteLine("Delete Entry\n");

        if (vault.Count == 0)
        {
            Console.WriteLine("No entries to delete");
            Console.WriteLine("Press any key to return to the menu");
            Console.ReadKey();
            return;
        }

        for (int i = 0; i < vault.Count; i++)
        {
            Console.WriteLine($"{i + 1}. {vault[i].Title}");
        }
        
        Console.Write("\nEnter the number of the entry you want to delete: ");
        string? input = Console.ReadLine();

        if (int.TryParse(input, out int number) && number >= 1 && number <= vault.Count)
        {
            Console.Write($"Delete '{vault[number - 1].Title}'? (y/n)");
            string? confirm = Console.ReadLine();

            if(confirm?.Trim().ToLower() == "y")
            {
            vault.RemoveAt(number - 1);
            SaveVault();
            Console.WriteLine("\nEntry Deleted");
            }
            else
            {
                Console.WriteLine("\nDeletion cancelled.");
            }
        }
        else
        {
            Console.WriteLine("\nInvalid Entry Number.");
        }

    Console.WriteLine("Press any key to return to the menu");
        Console.ReadKey();
    }

    static string GeneratePassword(int length = 16, bool useSymbols = true)
    {
        const string lower = "abcdefghijklmnopqrstuvwxyz";
        const string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const string digits = "0123456789";
        const string symbols = "!@#$%^&*()_+-=[]|{};':,/<>?";

        string validChars = lower + upper + digits + (useSymbols ? symbols : "");
        StringBuilder res = new();
        
        for (int i = 0; i < length; i++)
                {
            res.Append(validChars[RandomNumberGenerator.GetInt32(validChars.Length)]);
        }
        return res.ToString();
    }
}
