plugins { id("com.android.application") }
android {
 namespace = "com.dedsec.alienxbox"
 compileSdk = 35
 ndkVersion = "27.2.12479018"
 defaultConfig {
  applicationId = "com.dedsec.alienxbox"
  minSdk = 26
  targetSdk = 35
  versionCode = 3
  versionName = "0.2.1"
  ndk { abiFilters += "arm64-v8a" }
  externalNativeBuild { cmake { arguments += listOf("-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON", "-DANDROID_STL=c++_static") } }
 }
 externalNativeBuild { cmake { path = file("src/main/cpp/CMakeLists.txt"); version = "3.22.1" } }
 buildTypes { getByName("release") { isMinifyEnabled = false } }
}
