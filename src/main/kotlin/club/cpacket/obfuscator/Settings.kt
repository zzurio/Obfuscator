package club.cpacket.obfuscator

import com.google.gson.*
import java.lang.reflect.ParameterizedType
import java.lang.reflect.Type

/**
 * @author zzurio
 */

class Settings {
    // The Minecraft Forge modid.
    //val modId: String = ""

    // Files in the jar to exclude form the final jar.
    val ignoreJarEntries: MutableSet<String> = mutableSetOf()

    // Packages allowed to be altered/obfuscated.
    val validObfPackages: MutableSet<String> = mutableSetOf()

    // Classes that will not get obfuscated, for example, the entry point of the mod.
    val excludeObfClasses: MutableList<Regex> = mutableListOf()

    // Annotations that mark classes to be ignored by the obfuscation process.
    val excludeObfAnnotations: MutableList<Regex> = mutableListOf(
        Regex("^.*/Keep$"),
        Regex("""^org\.spongepowered\.asm\.*$""")
    )

    // Package where to put obfuscated classes.
    var obfPackage: String = ""

    // Package where to put obfuscated classes.
    val obfPackageMapping = mutableListOf<Pair<Regex, String>>()

    // Name obfuscation control.
    var enableClassObf: Boolean = true
    var enableFieldObf: Boolean = true
    var enableMethodObf: Boolean = true
    var enableLocalObf: Boolean = true

    // Format of obfuscated names.
    var obfNameFormat: ObfNameFormat = ObfNameFormat.WHITESPACE

    enum class ObfNameFormat { HEX, SEQUENTIAL, IL1J, WHITESPACE, BINARY, RANDOM }

    // Remove extra info added by kotlin, disable kotlin extra reflection utilities.
    var removeKotlinMetadata: Boolean = true

    // Remove extended type info, like List<Int>, becomes List<Object>.
    var removeSignatures: Boolean = true

    // Remove the name of the original source file for the class, in StackTraces shows (Unknown source).
    var removeSourceInfo: Boolean = true

    // Mark classes as synthetic to hide them from bad decompilers.
    var hideClassMembers: Boolean = true

    // Annotations for methods with event handlers, they need special metadata to work.
    val eventAnnotations: MutableSet<String> = mutableSetOf(
        "Lnet/minecraftforge/fml/common/eventhandler/SubscribeEvent;",
        "Lnet/minecraftforge/fml/common/Mod/EventHandler;"
    )

    // Replace constant numbers with complex expressions.
    //var numbersAsExpressions: Boolean = true

    // Keep a seed in every class and use it in the number expressions from [numbersAsExpressions].
    //var numbersAsExpressionsWithSeed: Boolean = true

    // Remove line number instructions.
    var removeLineNumbers: Boolean = true

    // Hide the content of strings.
    var stringMangling: Boolean = true

    // Flow obfuscation.
    //var enableFlowObf: Boolean = true

    // Encrypt strings.
    //var stringEncryption: Boolean = true

    // Map class => (field => value). Allow to override a field value on obfuscation.
    val fieldValueOverrides = mutableMapOf<String, Map<String, Any>>()

    // Keep the bytes of the class in an encrypted string.
    //var storeEncryptedClasses: Boolean = true

    // Class bytes' encryption key, use `./obf gen` to get a new key pair.
    //var classEncryptionKey: String = ""

    // String bytes encryption key.
    //var stringEncryptionKey: String = ""

    // Class bytes' encryption key, but only for mixins, as they have a lower security overall.
    //var mixinEncryptionKey: String = ""

    // Class names that must not be encrypted, for example, the entry point.
    //val excludeEncryptionClasses: MutableSet<Regex> = mutableSetOf()

    // Prefix of the mixin package, club.cpacket.client.mixin.
    //val mixinPackage: String = "mixin"

    // Remove normal function calls with calls to new functions that call the original function, to avoid non-obfuscated names mixed with obfuscated names.
    var addFunctionIndirections: Boolean = true

    // Replace regular functions calls with InvokeDynamic.
    //var useInvokeDynamic: Boolean = true

    // Classes where the performance is important, to avoid increasing the computation cost.
    val criticalPerformanceClasses: MutableSet<Regex> = mutableSetOf()

    companion object {
        private val gson = GsonBuilder()
            .setLenient()
            .setPrettyPrinting()
            .registerTypeAdapter(Regex::class.java, RegexSerializer)
            .registerTypeAdapter(Pair::class.java, PairSerializer)
            .create()

        fun fromJson(json: String): Settings {
            return gson.fromJson(json, Settings::class.java)
        }

        fun toJson(settings: Settings): String {
            return gson.toJson(settings)
        }
    }
}


object RegexSerializer : JsonSerializer<Regex>, JsonDeserializer<Regex> {
    override fun serialize(regex: Regex, ty: Type, ctx: JsonSerializationContext): JsonElement {
        return JsonPrimitive(regex.pattern)
    }

    override fun deserialize(json: JsonElement, ty: Type, ctx: JsonDeserializationContext): Regex {
        return Regex(json.asString)
    }
}

object PairSerializer : JsonSerializer<Pair<Any?, Any?>>, JsonDeserializer<Pair<Any?, Any?>> {
    override fun serialize(pair: Pair<Any?, Any?>, ty: Type, ctx: JsonSerializationContext): JsonElement {
        return JsonArray().also {
            it.add(ctx.serialize(pair.first))
            it.add(ctx.serialize(pair.second))
        }
    }

    override fun deserialize(json: JsonElement, ty: Type, ctx: JsonDeserializationContext): Pair<Any?, Any?> {
        val arr = json.asJsonArray
        val pty = ty as ParameterizedType
        return ctx.deserialize<Any?>(arr[0], pty.actualTypeArguments[0]) to ctx.deserialize<Any?>(
            arr[1],
            pty.actualTypeArguments[1]
        )
    }
}