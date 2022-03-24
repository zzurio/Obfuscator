package club.cpacket.obfuscator

import club.cpacket.obfuscator.drm.launchDrm
import java.io.File
import java.util.jar.JarFile

/**
 * @author zzurio
 */

object Main {
    @JvmStatic
    fun main(args: Array<String>) {
        val configName = args.getOrNull(0)
            ?: error("Missing first argument: Config file")

        val inputLocation = args.getOrNull(1) ?: error("Missing second argument: Input jar")
        val outputLocation = args.getOrNull(2) ?: error("Missing third argument: Output jar")

        val jar = JarFile(inputLocation)
        val output = File(outputLocation)

        val basename = inputLocation.substringAfterLast('/').substringBeforeLast('.')
        val mappingsLocation = args.getOrNull(3) ?: "maps-$basename.txt"

        val configFile = File(configName)
        if (!configFile.exists()) {
            error("Config file not found at '${configFile.absolutePath}'")
        }

        val settings = Settings.fromJson(configFile.readText())
        val obf = Obfuscator(jar, output, settings)
        obf.run()

        obf.exportMappings(File(mappingsLocation))
    }
}
