# UreSample.dll

Assembly .NET mínima usada pelos testes do monodis. Fonte: `tests/fixtures/src/dotnet-sample/Program.cs`.

Compilada com o compilador Roslyn do .NET SDK 8.0.134 (instalado neste servidor), sem NuGet:

    dotnet /usr/lib/dotnet/sdk/8.0.134/Roslyn/bincore/csc.dll -nologo -target:exe \
        -out:UreSample.dll -reference:<cada DLL de /usr/lib/dotnet/packs/Microsoft.NETCore.App.Ref/8.0.34/ref/net8.0> Program.cs

O teste confirma que o monodis lê o método `Calc::Add`.
