CARA BUILD APK
1. Install Android Studio (https://developer.android.com/studio).
2. File > Open > pilih folder NfcReader ini, tunggu Gradle sync selesai.
3. Build > Build Bundle(s) / APK(s) > Build APK(s).
4. APK ada di app/build/outputs/apk/debug/app-debug.apk
5. Salin ke HP, izinkan "install dari sumber tidak dikenal", lalu install.
Atau lewat terminal (jika sudah ada Gradle/wrapper): ./gradlew assembleDebug
