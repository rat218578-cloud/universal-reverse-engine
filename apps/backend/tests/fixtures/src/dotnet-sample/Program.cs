using System;
namespace Ure.Sample {
    public static class Calc {
        public static int Add(int a, int b) => a + b;
    }
    public class Program {
        public static void Main(string[] args) => Console.WriteLine("ure " + Calc.Add(2, 3));
    }
}
