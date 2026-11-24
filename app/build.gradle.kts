plugins { id("com.android.application") }
android {
 namespace = "com.dedsec.alienxbox"
 compileSdk = 35
 ndkVersion = "27.2.12479018"
 defaultConfig {
  applicationId = "com.dedsec.alienxbox"
  minSdk = 26
  targetSdk = 35
  versionCode = 7
  versionName = "0.3.3-v80"
  ndk { abiFilters += providers.gradleProperty("testAbi").orElse("arm64-v8a").get() }
  externalNativeBuild { cmake { arguments += listOf("-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON", "-DANDROID_STL=c++_static") } }
 }
 externalNativeBuild { cmake { path = file("src/main/cpp/CMakeLists.txt"); version = "3.22.1" } }
 buildTypes { getByName("release") { isMinifyEnabled = false } }
}
