// See https://aka.ms/new-console-template for more information
using EncryptDecrypt;


string textToEncrypt = "Amit Mohanty";
string encryptedText = Encryption_Works_With_CSharp_TypeScript.EncryptStringAES(textToEncrypt);
string decryptedText = Encryption_Works_With_CSharp_TypeScript.DecryptStringAES(encryptedText);
Console.WriteLine($"Original Text: {textToEncrypt} == Encrypted Text: {encryptedText} == Decrypted Text: {decryptedText}");


Console.ReadLine();