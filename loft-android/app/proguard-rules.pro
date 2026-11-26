# Generated native entry points are resolved by name through JNI/JNA.
-keep class net.aptist.loft.core.generated.** { *; }
-keep class net.aptist.loft.engine.** { *; }
-keep class go.** { *; }
-keep class com.sun.jna.** { *; }
-keepclasseswithmembernames class * { native <methods>; }
# JNA's desktop-only AWT bridge is never called on Android. These are the
# exact unavailable desktop classes reported by R8, not application classes.
-dontwarn java.awt.Component
-dontwarn java.awt.GraphicsEnvironment
-dontwarn java.awt.HeadlessException
-dontwarn java.awt.Window
