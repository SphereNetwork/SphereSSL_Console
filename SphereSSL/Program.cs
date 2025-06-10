using SphereSSL.View;

public class Program
{
    public static async Task Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        Console.WriteLine($"🌐 SPHERESSL ");

        await Spheressl.MainMenu();

    }
}
