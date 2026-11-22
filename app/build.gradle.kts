plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}
val nativeAbi=providers.gradleProperty("autowarpTestAbi").orElse("arm64-v8a").get()
require(nativeAbi in setOf("arm64-v8a","x86_64"))
android {
    namespace="dev.autowarp"
    compileSdk=35
    defaultConfig { applicationId="dev.autowarp"; minSdk=29; targetSdk=35; versionCode=67; versionName="0.2.3.38-background"; testInstrumentationRunner="androidx.test.runner.AndroidJUnitRunner"; ndk { abiFilters += nativeAbi } }
    buildFeatures { compose=true }
    testOptions { unitTests.isIncludeAndroidResources=true }
    packaging { jniLibs.useLegacyPackaging=true; dex.useLegacyPackaging=true }
    compileOptions { sourceCompatibility=JavaVersion.VERSION_17; targetCompatibility=JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget="17" }
    // One persistent signing identity for Android updates across CI runners.
    val stableKeystore=System.getenv("AUTOWARP_KEYSTORE")
    signingConfigs {
        if(!stableKeystore.isNullOrBlank()) {
            create("persistent") {
                storeFile=file(stableKeystore)
                storePassword=System.getenv("AUTOWARP_STORE_PASSWORD")
                keyAlias=System.getenv("AUTOWARP_KEY_ALIAS")
                keyPassword=System.getenv("AUTOWARP_KEY_PASSWORD")
            }
        }
    }
    buildTypes {
        getByName("debug") {
            if(!stableKeystore.isNullOrBlank()) signingConfig=signingConfigs.getByName("persistent")
        }
        getByName("release") {
            if(!stableKeystore.isNullOrBlank()) signingConfig=signingConfigs.getByName("persistent")
        }
    }
}
dependencies {
    implementation(files("libs/libbox.aar"))
    implementation(platform("androidx.compose:compose-bom:2025.04.01"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.work:work-runtime-ktx:2.10.1")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.yaml:snakeyaml:2.3")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:core-ktx:1.6.1")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    testImplementation("junit:junit:4.13.2")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testImplementation("com.squareup.okhttp3:okhttp-tls:4.12.0")
    testImplementation("org.robolectric:robolectric:4.14.1")
    testImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
    testImplementation("org.json:json:20240303")
}
tasks.withType<Test>().configureEach {
    systemProperty("neon.screenshotDir",layout.buildDirectory.dir("reports/neon").get().asFile.absolutePath)
    providers.gradleProperty("fixtureDir").orNull?.let { systemProperty("autowarp.fixtures", it) }
}


