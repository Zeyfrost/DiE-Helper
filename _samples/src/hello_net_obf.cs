// Test sample for the DiE Helper (never executed): .NET assembly whose type/method names imitate what
// name obfuscators emit - invisible "letters" (Hangul fillers U+3164 / U+FFA0), Cyrillic/Greek
// look-alikes, lIlI patterns and 1-letter names.
public static class ㅤㅤㅤ
{
    public static int a(int x) { return x + 1; }
    public static int b(int x) { return x * 2; }
    public static int c(int x) { return x - 3; }
}

public static class lIlIlIlIlIlI
{
    public static int IlIlIlIl(int x) { return x ^ 0x55; }
    public static int lllIIIlll(int x) { return x | 1; }
    public static int ﾠﾠ(int x) { return x & 7; }
}

public static class ЅЅΡЅ
{
    public static int ㅤzㅤ(int x) { return x << 1; }
    public static int k(int x) { return x >> 1; }
    public static int ﾠㅤw(int x) { return ~x; }
}

public static class Program
{
    public static void Main()
    {
        int v = lIlIlIlIlIlI.IlIlIlIl(ㅤㅤㅤ.a(1));
        v = ЅЅΡЅ.k(lIlIlIlIlIlI.lllIIIlll(v));
        System.Console.WriteLine(v);
    }
}
