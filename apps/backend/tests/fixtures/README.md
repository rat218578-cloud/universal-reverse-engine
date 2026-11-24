# Fixtures reais

- `real/fixture.apk`: APK gerado pelo Apktool 2.7.0 a partir de `src/fixture-apk` (smali compilado para
  `classes.dex`, `resources.arsc` e `AndroidManifest.xml` binário, linkados com o aapt do sistema).
- `real/libfixture.so`: biblioteca ELF x86-64 compilada com GCC (`-shared -fPIC -O1 -s`) a partir de uma
  única função. Usada para testar o LIEF e os caminhos `lib/<abi>/*.so`.

Regerar `fixture.apk` (dentro de `src/fixture-apk`): `apktool b -o ../../real/fixture.apk .`
