using System;
using System.IO;
using System.Collections.Generic;
using System.Text.Json;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

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

    static byte[] GenerateSalt()
    {
        return RandomNumberGenerator.GetBytes(16);
    }

    static bool VerifyMasterPassword(string password)
    {
        string stored = File.ReadAllText("master.txt");
        string[] parts = stored.Split(':');

        byte[] salt = Convert.FromBase64String(parts[0]);
        byte[] storedHash = Convert.FromBase64String(parts[1]);

        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            100_000,
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
            100_000,
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
        
        Console.Write("Enter master password: ");
        string enteredPassword = ReadPassword()!;

        if (!VerifyMasterPassword(enteredPassword))
        {
            Console.WriteLine("Incorrect master password");
            Console.ReadKey();
            return;
        }
        vault = LoadVault(enteredPassword);

        bool running = true;
        
        while (running)
        {
            Console.Clear();
            Console.WriteLine("1. View Passwords");
            Console.WriteLine("2. Add Entry");
            Console.WriteLine("3. Exit");
            Console.WriteLine("4. Delete Entry");
            Console.WriteLine("5. Search Entries");
            Console.WriteLine("6. Edit Entries");
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
                    Console.WriteLine("\nAdios!");
                    running = false;
                    break;
                case "4":
                    DeleteEntry();
                    break;
                case "5":
                    SearchEntries();
                    break;
                case "6":
                    EditEntry();
                    break;
                default:
                    Console.WriteLine("\nInvalid option try again broski");
                    Console.ReadKey();
                    break;
            }
        }
    }

    static string ReadPassword()
    {
        StringBuilder password = new StringBuilder();

        while(true)
        {
            ConsoleKeyInfo key = Console.ReadKey(true);

            if (key.Key == ConsoleKey.Enter)
            break;

            if (key.Key == ConsoleKey.Backspace && password.Length > 0)
            {
                password.Length--;
                Console.Write("\b \b");
            }
            else if (!char.IsControl(key.KeyChar))
            {
                password.Append(key.KeyChar);
                Console.Write("*");
            }
        }
        Console.WriteLine();
        return password.ToString();
    }
    static void SetupMasterPassword()
    {
        Console.Write("Create a master password: ");
        string masterPassword = ReadPassword()!;

        byte[] salt = GenerateSalt();

        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
            masterPassword,
            salt,
            100_000,
            HashAlgorithmName.SHA256,
            32
        );
        

        File.WriteAllText("master.txt",
            Convert.ToBase64String(salt) + ":" +
            Convert.ToBase64String(hash));

        Console.WriteLine("Master Password created.");

        Console.WriteLine("Press any key to return to menu");

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
        return JsonSerializer.Deserialize<List<PasswordEntry>>(plain)?? new List<PasswordEntry>();
    }
    
    private static void SaveVault()
    {
        byte[] plain = JsonSerializer.SerializeToUtf8Bytes(vault);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] cipher = new byte[plain.Length];
        byte[] tag = new byte[16];

        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plain, cipher, tag);

        File.WriteAllBytes(VaultPath,
        vaultSalt.Concat(nonce).Concat(tag).Concat(cipher).ToArray());
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
                Console.WriteLine($"    Password: {entry.Password}");
                Console.WriteLine($"    URL: {entry.URL}");
                Console.WriteLine();
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
                
                Console.WriteLine($"Password: {entry.Password}");

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

        Console.Write($"New username/email ({entry.Username}): ");
        string username = Console.ReadLine() ?? "";

        Console.Write("New password (leave blank to keep current):  ");
        string password = ReadPassword();

        Console.Write($"New URL ({entry.URL}): ");
        string url = Console.ReadLine() ?? "";

        if (!string.IsNullOrWhiteSpace(username))
            entry.Username = username;

        if (!string.IsNullOrEmpty(password))
            entry.Password = password;

        if (!string.IsNullOrWhiteSpace(url))
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

        if (int.TryParse(input, out int number) &&
            number >= 1 &&
            number <= vault.Count)
        {
            vault.RemoveAt(number - 1);
            SaveVault();

            Console.WriteLine("\nEntry Deleted");
        }
        else
        {
            Console.WriteLine("\nInvalid Entry Number.");
        }

    Console.WriteLine("Press any key to return to the menu");
        Console.ReadKey();
    }
    
}
