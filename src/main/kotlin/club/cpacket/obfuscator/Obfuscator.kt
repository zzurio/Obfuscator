package club.cpacket.obfuscator

import org.objectweb.asm.*
import org.objectweb.asm.tree.*
import java.io.File
import java.security.MessageDigest
import java.time.Instant
import java.util.*
import java.util.jar.JarFile
import kotlin.collections.ArrayDeque
import kotlin.experimental.xor
import kotlin.random.Random

private const val KOTLIN_METADATA_ANNOTATION = "Lkotlin/Metadata;"
private const val ANNOTATION_REF = "java/lang/annotation/Annotation"
private val CLASS_REF_REGEX = """^[^./()\s%\]]+(\.[^./()\s%\]]+)+$""".toRegex()
private val STRING_REF_REGEX = """^[^./()\s%]+(/[^./()\s%]+)+$""".toRegex()
private val STRING_REF2_REGEX = """^[^\[./()\s%][^./()\s%]+(\.[^./()\s%]+)+$""".toRegex()
private val HEX_ARRAY = "0123456789ABCDEF".toCharArray()
private val SEQUENTIAL_ARRAY = "abcdefghijklmnopqrstuvwxyz".toCharArray()
private val IL1J_ARRAY = "il1j".toCharArray()
private val WHITESPACE_ARRAY = " \t\r\u000b\u0001\u0002\u0003\u0004\u0005\u0006\u0007\u0008".toCharArray()
private val BINARY_ARRAY = "01".toCharArray()
private val RANDOM_ARRAY = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#%*1234567890".toCharArray()

/**
 * @author zzurio
 */

class Obfuscator(
    private val inputJar: JarFile,
    private val outputJar: File,
    private val settings: Settings,
    private val tmpFolder: File = File("run/output")
) {

    private val classFiles = mutableMapOf<String, ClassFile>()
    private val newFunctions = mutableMapOf<String, FunctionPrototype>()
    private val generatedNames = mutableSetOf<String>()

    //private val invokeMap = mutableMapOf<String, String>()
    private val fileChecksums = mutableMapOf<String, String>()
    private val sha256 = MessageDigest.getInstance("SHA-256")

    fun run() {
        info("Cleaning temporary folder...")
        if (tmpFolder.exists()) tmpFolder.deleteRecursively()
        tmpFolder.mkdir()

        info("Cleaning cache...")
        classFiles.clear()

        info("Extracting jar...")
        extractJar()

        info("Exploring files...")
        exploreFolder(tmpFolder)

        if (settings.addFunctionIndirections) {
            info("Adding function indirections...")
            for (classFile in sortedClasses()) {
                addFunctionIndirections(classFile)
            }

            info("Creating new classes...")
            newFunctions.values
                .groupBy { it.owner }
                .forEach { (owner, methods) ->
                    createIndirectionClass(owner, methods)
                }
        }

        info("Sorting classes...") // 1447
        val sortedClasses = sortedClasses()

        info("Generating obfuscated names...")
        for (classFile in sortedClasses) {
            generateObfNames(classFile)
        }

        info("Updating references...")
        for (classFile in sortedClasses) {
            if (!classFile.editable) continue

            changeNames(classFile)

            if (settings.removeSignatures) {
                removeSignatures(classFile)
            }

            if (settings.hideClassMembers) {
                hideClassMembers(classFile)
            }

            if (settings.removeSourceInfo) {
                classFile.modified = true
                if (classFile.classNode.sourceFile != null) {
                    classFile.classNode.sourceFile = classFile.obfName + ".java"
                }
                classFile.classNode.sourceDebug = null
            }

            /*if (settings.numbersAsExpressions) {
                replaceNumbers(classFile)
            }*/
            if (settings.removeLineNumbers) {
                removeLineNumbers(classFile)
            }

            /*if (settings.enableFlowObf) {
                flowObf(classFile.classNode)
            }*/
        }

        /*if (settings.useInvokeDynamic) {
            info("Adding basic indirections...")
            for (classFile in sortedClasses) {
                addInvokeDynamic(classFile)
            }
        }*/

        /*if (invokeMap.isNotEmpty()) {
            info("Saving invoke map...")
            val mappings = invokeMap.map { (key, value) ->
                Encryption.encryptString(settings.stringEncryptionKey, key) + "," +
                        Encryption.encryptString(settings.stringEncryptionKey, value)
            }.joinToString("\n")

            val encMappings = Encryption.encryptString(settings.classEncryptionKey, mappings)

            File(tmpFolder, "mappings.dat")
                .writeBytes(Base64.getDecoder().decode(encMappings))
        }*/

        /*if (settings.stringEncryption) {
            info("Encrypting strings...")
            for (classFile in sortedClasses) {
                encryptStrings(classFile)
            }
        }*/

        if (settings.stringMangling) {
            info("Mangling strings...")
            val offsetKey = Random.nextLong()

            for (classFile in sortedClasses) {
                mangleStrings(classFile, offsetKey)
            }

            val clazz = ClassLoader.getSystemResourceAsStream("inject/club/cpacket/obfuscator/Strings.class")!!
            val target = File(tmpFolder, "club/cpacket/obfuscator/Strings.class")
            target.parentFile.mkdirs()
            target.writeBytes(clazz.readBytes())

            val file = exploreClass(target)

            file.classNode.version = Opcodes.V1_8
            file.modified = true
            settings.fieldValueOverrides["club.cpacket.obfuscator.Strings"] = mapOf("KEY" to offsetKey)
        }

        info("Overriding values...")
        for (classFile in classFiles.values) {
            overrideValues(classFile)
        }

        /*if (settings.storeEncryptedClasses) {
            info("Encrypting classes...")
            for (classFile in classFiles.values) {
                encryptClass(classFile)
            }
        }*/

        info("Saving classes...")
        for (classFile in classFiles.values) {
            saveClass(classFile)
        }

        info("Removing empty folders...")
        cleanFolders(tmpFolder)

        info("Remove trash...")
        removeTrash()

        info("Calculating checksums...")
        calculateChecksums(tmpFolder)

        if (fileChecksums.isNotEmpty()) {
            info("Saving checksums...")
            //val data = fileChecksums.map { (key, value) -> "$value,$key" }.joinToString("\n")

            //val encData = Encryption.encryptString(settings.classEncryptionKey, data)

            //File(tmpFolder, "checksums.dat")
            //    .writeBytes(Base64.getDecoder().decode(encData))
        }

        info("Building jar...")
        buildJar()

        info("Done!")
    }

    private fun calculateChecksums(folder: File) {
        if (folder.isDirectory) {
            folder.listFiles()?.forEach { calculateChecksums(it) }
        } else if (folder.isFile) {
            val path = folder.toRelativeString(tmpFolder)

            if (path.startsWith("META-INF/")) return

            sha256
                .also { it.reset() }
                .digest(folder.readBytes())
                .let { bytesToHex(it) }
                .let { fileChecksums[path] = it }
        }
    }

    private fun bytesToHex(hash: ByteArray): String = buildString {
        for (i in hash.indices) {
            val hex = Integer.toHexString(0xff and hash[i].toInt())
            if (hex.length == 1) {
                append('0')
            }
            append(hex)
        }
    }

    private fun info(msg: String) {
        println("[${Instant.now()}] $msg")
    }

    private fun buildJar() {

        val cmd = listOf(
            "jar",
            "cmf",
            "${tmpFolder.absolutePath}/META-INF/MANIFEST.MF",
            "${outputJar.absolutePath}",
            "-C",
            "${tmpFolder.absolutePath}",
            "."
        )

        ProcessBuilder()
            .command(cmd)
            .inheritIO()
            .start()
            .waitFor()
    }


    private fun removeTrash() {
        File(tmpFolder, "LICENSE.txt").takeIf { it.exists() }?.delete()
        File(tmpFolder, "META-INF/fml_cache_annotation.json").takeIf { it.exists() }?.delete()
        File(tmpFolder, "META-INF/fml_cache_class_versions.json").takeIf { it.exists() }?.delete()
        //File(tmpFolder, "META-INF/${settings.modId}.kotlin_module").takeIf { it.exists() }?.delete()
        File(tmpFolder, "META-INF/kotlin-stdlib.kotlin_module").takeIf { it.exists() }?.delete()
        File(tmpFolder, "META-INF/kotlin-stdlib-coroutines.kotlin_module").takeIf { it.exists() }?.delete()
        File(tmpFolder, "META-INF/kotlin-stdlib-jdk8.kotlin_module").takeIf { it.exists() }?.delete()
    }

    private fun cleanFolders(folder: File) {
        if (!folder.isDirectory) return
        folder.listFiles()?.forEach { cleanFolders(it) }

        val contents = folder.list()
        if (contents == null || contents.isEmpty()) {
            folder.delete()
        }
    }

    private fun saveClass(classFile: ClassFile) {
        if (!classFile.modified) return

        val file = File("${tmpFolder.path}/${classFile.obfName}.class")
        file.parentFile.mkdirs()

        if (classFile.originalFile != null && classFile.originalFile.absolutePath != file.absolutePath && classFile.editable) {
            classFile.originalFile.delete()
        }

        classFile.classNode.version = Opcodes.V1_8

        val bytes = ClassWriter(ClassWriter.COMPUTE_MAXS).also { classFile.classNode.accept(it) }.toByteArray()
        file.writeBytes(bytes)
    }

    /*private fun encryptClass(classFile: ClassFile) {
        if (!classFile.editable) return
        if (settings.excludeEncryptionClasses.any { regex -> regex.matches(classFile.javaName) }) return

        classFile.modified = true

        val node = classFile.classNode
        node.version = Opcodes.V1_8
        val w = ClassWriter(ClassWriter.COMPUTE_MAXS).also { node.accept(it) }

        // Check for mixin class.
        val mixin = classFile.javaName.startsWith(settings.mixinPackage)
        val key = if (mixin) settings.mixinEncryptionKey else settings.classEncryptionKey

        val encrypted = Encryption.encryptByteArray(key, w.toByteArray())

        classFile.classNode = ClassNode().apply {
            version = Opcodes.V1_8
            access = Opcodes.ACC_PUBLIC // node.access
            name = node.name
            signature = null // node.signature
            superName = "java/lang/Object" // node.superName

            encrypted.chunked(16_000).forEachIndexed { index, chunk ->
                val name = if (index == 0) "__SAFE__" else "__SAFE_${index}__"

                fields.add(
                    FieldNode(
                        Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL /* Opcodes.ACC_SYNTHETIC */,
                        name,
                        "Ljava/lang/String;",
                        null,
                        chunk
                    )
                )
            }
        }
    }*/

    private fun extractJar() {
        for (entry in inputJar.entries()) {
            if (entry.isDirectory || entry.name in settings.ignoreJarEntries) continue
            val outputFile = File(tmpFolder, entry.name)
            val fileBytes = inputJar.getInputStream(entry).readBytes()

            outputFile.parentFile.mkdirs()
            outputFile.writeBytes(fileBytes)
        }
    }

    private fun exploreFolder(folder: File) {
        if (folder.isDirectory) {
            folder.listFiles()?.forEach {
                exploreFolder(it)
            }
        } else if (folder.extension == "class") {
            exploreClass(folder)
        }
    }

    private fun exploreClass(file: File): ClassFile {
        val reader = ClassReader(file.readBytes())
        val classNode = ClassNode()
        reader.accept(classNode, 0)

        val javaName = classNode.name.replace('/', '.')
        val editable = settings.validObfPackages.any { packageName -> javaName.startsWith(packageName) }

        val classFile = ClassFile(
            originalFile = file,
            classNode = classNode,
            editable = editable
        )
        classFiles[classNode.name] = classFile

        exploreMethods(classFile)
        exploreFields(classFile)

        return classFile
    }

    private fun sortedClasses(): List<ClassFile> {
        val result = mutableListOf<ClassFile>()
        val visited = mutableSetOf<String>()
        val nodeParents: MutableMap<String, MutableSet<String>> = mutableMapOf()
        val keys = classFiles.keys

        classFiles.values.forEach { file ->
            val dependencies = file.dependencies.toMutableSet()

            dependencies.retainAll { it in keys }

            nodeParents[file.name] = dependencies
        }

        while (visited.size < classFiles.size) {
            val processableClasses = nodeParents.filter { it.value.isEmpty() && it.key !in visited }.map { it.key }

            processableClasses.forEach { name ->
                result += classFiles[name] ?: error("Invalid name: $name")
                visited += name
            }

            nodeParents.values.forEach { value ->
                value.removeAll(visited)
            }
        }

        return result
    }

    private fun exploreMethods(classFile: ClassFile) {
        val perf = settings.criticalPerformanceClasses.any { regex -> regex.matches(classFile.javaName) }

        classFile.classNode.methods.forEach { method ->
            val m = ClassMethod(method)
            m.isCriticalForPerformance = m.isCriticalForPerformance || perf
            classFile.methods[key(m.name, m.desc)] = m
        }
    }

    private fun exploreFields(classFile: ClassFile) {
        classFile.classNode.fields.forEach { field ->
            classFile.fields[key(field.name, field.desc)] = ClassField(field)
        }
    }

    private fun generateObfNames(file: ClassFile) {
        if (!file.editable) return

        val excludeClass = settings.excludeObfClasses.any { it.matches(file.javaName) }
        if (excludeClass) return

        val annotations =
            (file.classNode.visibleAnnotations ?: emptyList()) + (file.classNode.invisibleAnnotations ?: emptyList())
        val excludeAnnotation = annotations.any { annotation ->
            settings.excludeObfAnnotations.any { it.matches(annotation.desc) }
        }

        if (excludeAnnotation) return

        if (settings.enableClassObf) {
            val pkg = settings.obfPackageMapping
                .find { it.first.matches(file.javaName) }
                ?.second
                ?: settings.obfPackage

            val obfSimpleName = genObfName()
            file.obfName = pkg.replace(".", "/") + '/' + obfSimpleName
        }

        if (settings.enableMethodObf) {
            for (method in file.methods.values) {
                if (isSpecialMethod(method.methodNode.name)) continue

                val excluded = method.methodNode.visibleAnnotations?.any { annotation ->
                    settings.excludeObfAnnotations.any { it.matches(annotation.desc) }
                } ?: false
                if (excluded) continue

                if (file.dependencies.isNotEmpty()) {
                    val overrideMethod = findOverrideMethod(method, file) ?: continue

                    if (overrideMethod === method) {
                        method.obfName = genObfName()
                    } else {
                        method.obfName = overrideMethod.obfName
                    }
                    continue
                }
                method.obfName = genObfName()
            }
        }

        if (settings.enableFieldObf) {
            for (field in file.fields.values) {
                val excluded = field.fieldNode.visibleAnnotations?.any { annotation ->
                    settings.excludeObfAnnotations.any { it.matches(annotation.desc) }
                } ?: false
                if (excluded) continue
                field.obfName = genObfName()
            }
        }
    }

    private fun findOverrideMethod(method: ClassMethod, ownerClass: ClassFile): ClassMethod? {
        val methodKey = key(method.name, method.desc)
        var missingData = false

        val queue = ArrayDeque<String>()
        val visited = mutableSetOf<String>()

        queue.addAll(ownerClass.dependencies)
        visited.addAll(ownerClass.dependencies)

        while (queue.isNotEmpty()) {
            val current = queue.removeFirst()
            val classFile = classFiles[current]

            if (classFile == null) {
                missingData = true
                continue
            }

            val nextDependencies = classFile.dependencies.filter { !visited.contains(it) }
            queue.addAll(nextDependencies)
            visited.addAll(nextDependencies)

            if (methodKey in classFile.methods) {
                return classFile.methods[methodKey]
            }
        }

        return if (missingData) null else method
    }

    private fun changeNames(file: ClassFile) {
        if (!file.editable) return
        file.modified = true

        val classNode = file.classNode
        classNode.name = file.obfName

        classNode.visibleAnnotations?.let { annotations ->
            if (settings.removeKotlinMetadata) {
                annotations.removeAll { it.desc == KOTLIN_METADATA_ANNOTATION }
            }

            annotations.forEach { annotation ->
                changeAnnotationNames(annotation)
            }
        }

        classNode.superName = mapClassName(classNode.superName)
        classNode.interfaces = classNode.interfaces.map(::mapClassName)

        classNode.outerClass = mapClassName(classNode.outerClass)
        classNode.outerMethod = null
        classNode.outerMethodDesc = null

        classNode.innerClasses?.forEach { inner ->
            inner.name = mapInternalName(inner.name)
            inner.outerName = mapClassName(inner.outerName)

            val innerName = inner.name.substringAfterLast('/')
            inner.innerName = if ("$" in innerName) innerName.substringAfterLast('$') else innerName
        }

        file.methods.forEach { (_, method) ->
            method.methodNode.name = method.obfName

            method.methodNode.annotationDefault?.let { def ->
                if (def is Array<*>) {
                    @Suppress("UNCHECKED_CAST")
                    def as Array<String>
                    def[0] = mapDescriptor(def[0])
                }
            }

            val annotations = method.methodNode.visibleAnnotations
            val excluded = annotations != null && settings.eventAnnotations.any { eventDesc ->
                annotations.any { it.desc == eventDesc }
            }

            if (!excluded) {
                method.methodNode.desc = mapDescriptor(method.desc)
            }

            if (settings.enableLocalObf) {
                method.methodNode.localVariables?.forEach { ins ->
                    if (ins.name != "this") {
                        val obfName = genObfName("l")
                        method.locals[ins.name] = obfName
                        ins.name = obfName
                    }
                    ins.desc = mapDescriptor(ins.desc)
                }
            }

            changeInstructionNames(method.methodNode.instructions)
        }

        file.fields.forEach { (_, field) ->
            field.fieldNode.name = field.obfName
            field.fieldNode.desc = mapDescriptor(field.desc)
        }
    }

    private fun changeInstructionNames(instructions: InsnList) {
        instructions.toArray().forEach ins@{ ins ->
            if (ins is MethodInsnNode) {
                ins.name = mapMethodName(ins.owner, ins.name, ins.desc)
                ins.owner = if (isInternalName(ins.owner)) mapInternalName(ins.owner) else mapDescriptor(ins.owner)
                ins.desc = mapDescriptor(ins.desc)
            }

            if (ins is InvokeDynamicInsnNode) {
                ins.name = mapMethodName(ins.desc, ins.name, ins.bsmArgs[0].toString())
                ins.desc = mapDescriptor(ins.desc)
                ins.bsm = Handle(
                    ins.bsm.tag,
                    mapClassName(ins.bsm.owner),
                    ins.bsm.name,
                    mapDescriptor(ins.bsm.desc)
                )
                ins.bsmArgs.forEachIndexed args@{ index, arg ->
                    if (arg is Type) {
                        ins.bsmArgs[index] = mapTypeDescriptor(arg)
                    }
                    if (arg is Handle) {
                        val methodName = mapMethodName(arg.owner, arg.name, arg.desc)

                        ins.bsmArgs[index] = Handle(
                            arg.tag,
                            mapClassName(arg.owner),
                            methodName,
                            mapDescriptor(arg.desc)
                        )
                    }
                }
            }

            if (ins is FieldInsnNode) {
                ins.name = mapFieldName(ins.owner, ins.name, ins.desc)
                ins.owner = if (isInternalName(ins.owner)) mapInternalName(ins.owner) else mapDescriptor(ins.owner)
                ins.desc = mapDescriptor(ins.desc)
            }

            if (ins is TypeInsnNode) {
                ins.desc = if (isInternalName(ins.desc)) mapInternalName(ins.desc) else mapDescriptor(ins.desc)
            }

            if (ins is LdcInsnNode) {
                val constant = ins.cst
                when {
                    constant is Type -> {
                        ins.cst = mapTypeDescriptor(constant)
                    }
                    constant is String && constant.contains(STRING_REF_REGEX) -> {
                        ins.cst = mapInternalName(constant)
                    }
                    constant is String && constant.contains(STRING_REF2_REGEX) -> {
                        val base = constant.replace(".", "/")
                        val newValue = mapInternalName(base)
                        if (base != newValue) {
                            ins.cst = newValue.replace("/", ".")
                        }
                    }
                }
            }

            if (ins is FrameNode) {
                ins.local = ins.local?.map {
                    if (it is String) {
                        if (isInternalName(it)) mapInternalName(it) else mapDescriptor(it)
                    } else it
                }
                ins.stack = ins.stack?.map {
                    if (it is String) {
                        if (isInternalName(it)) mapInternalName(it) else mapDescriptor(it)
                    } else it
                }
            }
        }
    }

    private fun changeAnnotationNames(annotation: AnnotationNode) {
        annotation.desc = mapDescriptor(annotation.desc)
        val values = annotation.values ?: return

        values.chunked(2).forEachIndexed { index, (_, value) ->
            val newValue = when (value) {
                is String -> {
                    if (value.contains(CLASS_REF_REGEX)) {
                        mapInternalName(value.replace(".", "/")).replace("/", ".")
                    } else {
                        value
                    }
                }
                is Array<*> -> {
                    @Suppress("UNCHECKED_CAST")
                    val valueArray = value as Array<String>

                    valueArray[0] = mapDescriptor(valueArray[0])
                    valueArray
                }
                else -> value
            }
            values[index * 2 + 1] = newValue
        }

        annotation.values = values
    }

    private fun removeSignatures(file: ClassFile) {
        if (!file.editable) return

        file.modified = true
        file.classNode.signature = null

        file.methods.forEach { (_, method) ->
            val annotations = method.methodNode.visibleAnnotations

            val excluded = annotations != null && settings.eventAnnotations.any { eventDesc ->
                annotations.any { it.desc == eventDesc }
            }

            if (!excluded) {
                method.methodNode.signature = null
            }
        }

        file.fields.forEach { (_, field) ->
            val annotations = field.fieldNode.visibleAnnotations

            val excluded = annotations != null && settings.eventAnnotations.any { eventDesc ->
                annotations.any { it.desc == eventDesc }
            }

            if (!excluded) {
                field.fieldNode.signature = null
            }
        }
    }

    private fun hideClassMembers(file: ClassFile) {
        if (!file.editable) return
        file.modified = true

        if (!file.dependencies.contains(ANNOTATION_REF)) {
            file.classNode.access = file.classNode.access or Opcodes.ACC_SYNTHETIC
        }

        file.methods.forEach { (_, method) ->
            method.methodNode.access = method.methodNode.access or Opcodes.ACC_SYNTHETIC
        }

        file.fields.forEach { (_, field) ->
            field.fieldNode.access = field.fieldNode.access or Opcodes.ACC_SYNTHETIC
        }
    }

    /*private fun replaceNumbers(file: ClassFile) {
        file.modified = true
        var hasNumbers = false
        for (method in file.methods.values) {
            val insn = method.methodNode.instructions

            for (node in insn) {
                val constant = node.getConstant() ?: continue
                when (constant) {
                    is Int -> {
                        hasNumbers = true
                        val left = if (settings.numbersAsExpressionsWithSeed) {
                            file.seedInt
                        } else {
                            Random.nextInt(0x7FFFFFFF)
                        }

                        val sub = Random.nextInt(0x7FFFFFFF)
                        val right = (left xor constant) - sub

                        insn.insert(node, InsnList().also {
                            if (settings.numbersAsExpressionsWithSeed) {
                                it += FieldInsnNode(Opcodes.GETSTATIC, file.obfName, "ISEED", "I")
                            } else {
                                it += LdcInsnNode(left)
                            }
                            it += LdcInsnNode(right)
                            it += LdcInsnNode(sub)
                            it += InsnNode(Opcodes.IADD)
                            it += InsnNode(Opcodes.IXOR)
                        })
                        insn.remove(node)
                    }
                    is Long -> {
                        hasNumbers = true
                        val left = if (settings.numbersAsExpressionsWithSeed) {
                            file.seedLong
                        } else {
                            Random.nextLong(0x7FFFFFFF)
                        }
                        val sub = Random.nextLong(0x7FFFFFFF)
                        val right = (left xor constant) - sub

                        insn.insert(node, InsnList().also {
                            if (settings.numbersAsExpressionsWithSeed) {
                                it += FieldInsnNode(Opcodes.GETSTATIC, file.obfName, "LSEED", "J")
                            } else {
                                it += LdcInsnNode(left)
                            }
                            it += LdcInsnNode(right)
                            it += LdcInsnNode(sub)
                            it += InsnNode(Opcodes.LADD)
                            it += InsnNode(Opcodes.LXOR)
                        })
                        insn.remove(node)
                    }
                    is Float -> {
                        hasNumbers = true
                        val left = if (settings.numbersAsExpressionsWithSeed) {
                            file.seedInt
                        } else {
                            Random.nextInt(0x7FFFFFFF)
                        }
                        val sub = Random.nextInt(0x7FFFFFFF)
                        val right = (left xor constant.toRawBits()) - sub

                        insn.insert(node, InsnList().also {
                            if (settings.numbersAsExpressionsWithSeed) {
                                it += FieldInsnNode(Opcodes.GETSTATIC, file.obfName, "ISEED", "I")
                            } else {
                                it += LdcInsnNode(left)
                            }
                            it += LdcInsnNode(right)
                            it += LdcInsnNode(sub)
                            it += InsnNode(Opcodes.IADD)
                            it += InsnNode(Opcodes.IXOR)
                            it += MethodInsnNode(
                                Opcodes.INVOKESTATIC,
                                "java/lang/Float",
                                "intBitsToFloat",
                                "(I)F",
                                false
                            )
                        })
                        insn.remove(node)
                    }
                    is Double -> {
                        hasNumbers = true
                        val left = if (settings.numbersAsExpressionsWithSeed) {
                            file.seedLong
                        } else {
                            Random.nextLong(0x7FFFFFFF)
                        }
                        val sub = Random.nextLong(0x7FFFFFFF)
                        val right = (left xor constant.toRawBits()) - sub

                        insn.insert(node, InsnList().also {
                            if (settings.numbersAsExpressionsWithSeed) {
                                it += FieldInsnNode(Opcodes.GETSTATIC, file.obfName, "LSEED", "J")
                            } else {
                                it += LdcInsnNode(left)
                            }
                            it += LdcInsnNode(right)
                            it += LdcInsnNode(sub)
                            it += InsnNode(Opcodes.LADD)
                            it += InsnNode(Opcodes.LXOR)
                            it += MethodInsnNode(
                                Opcodes.INVOKESTATIC,
                                "java/lang/Double",
                                "longBitsToDouble",
                                "(J)D",
                                false
                            )
                        })
                        insn.remove(node)
                    }
                }
            }
        }

        if (settings.numbersAsExpressionsWithSeed && hasNumbers) {
            val inter = file.classNode.access and Opcodes.ACC_INTERFACE != 0
            val access = if (inter) Opcodes.ACC_PUBLIC else Opcodes.ACC_PRIVATE

            file.classNode.fields.add(
                FieldNode(
                    access or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL or Opcodes.ACC_SYNTHETIC,
                    "ISEED",
                    "I",
                    null,
                    0
                )
            )

            file.classNode.fields.add(
                FieldNode(
                    access or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL or Opcodes.ACC_SYNTHETIC,
                    "LSEED",
                    "J",
                    null,
                    0L
                )
            )

            var clinit = file.classNode.methods
                .find { it.name == "<clinit>" }

            if (clinit == null) {
                clinit = MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, arrayOf())
                file.classNode.methods.add(clinit)
                clinit.instructions.add(InsnNode(Opcodes.RETURN))
            }

            clinit.instructions.insertBefore(clinit.instructions.first, InsnList().also {

                val iname = genObfName()
                val (ia, ib) = encodeInt(file.seedInt, iname)

                it += LdcInsnNode("${settings.modId}:${Encryption.encryptString(settings.stringEncryptionKey, iname)}")
                it += LdcInsnNode(ia)
                it += LdcInsnNode(ib)
                it += MethodInsnNode(
                    Opcodes.INVOKESTATIC,
                    "club/cpacket/drm/EncryptionUtils",
                    "decodeInt",
                    "(Ljava/lang/String;II)I",
                    false
                )
                it += FieldInsnNode(Opcodes.PUTSTATIC, file.obfName, "ISEED", "I")

                val lname = genObfName()
                val (la, lb) = encodeLong(file.seedLong, lname)
                val lString = Encryption.encryptString(settings.stringEncryptionKey, lname)

                it += LdcInsnNode("${settings.modId}:$lString")
                it += LdcInsnNode(la)
                it += LdcInsnNode(lb)
                it += MethodInsnNode(
                    Opcodes.INVOKESTATIC,
                    "club/cpacket/drm/EncryptionUtils",
                    "decodeLong",
                    "(Ljava/lang/String;JJ)J",
                    false
                )
                it += FieldInsnNode(Opcodes.PUTSTATIC, file.obfName, "LSEED", "J")
            })
        }
    }*/

    private fun encodeInt(key: Int, file: String): Pair<Int, Int> {
        val a = Random.nextInt()
        val b = murmurOAAT32(file)

        return Pair(
            key xor a xor b,
            java.lang.Integer.rotateLeft(a.inv(), 15) xor 0x0F0F0F0F xor 0x55555555
        )
    }

    private fun encodeLong(key: Long, file: String): Pair<Long, Long> {
        val a = Random.nextLong()
        val b = murmurOAAT64(file)

        return Pair(
            key xor a xor b,
            java.lang.Long.rotateLeft(a.inv(), 47) xor 0x0F0F0F0F0F0F0F0F xor 0x5555555555555555
        )
    }

    private fun removeLineNumbers(file: ClassFile) {
        file.modified = true
        for (method in file.methods.values) {
            val insn = method.methodNode.instructions

            for (node in insn) {
                if (node is LineNumberNode) {
                    insn.remove(node)
                }
            }
        }
    }

    private fun addFunctionIndirections(file: ClassFile) {
        if (!file.editable) return

        file.modified = true

        val newOwner = file.name.substringBeforeLast("/") + "/Ind" +
                file.name.substringAfterLast('/').capitalize()

        for (method in file.methods.values) {
            val insn = method.methodNode.instructions

            for (node in insn) {
                if (node !is MethodInsnNode || isSpecialMethod(node.name)) continue

                when (node.opcode) {
                    Opcodes.INVOKEVIRTUAL, Opcodes.INVOKESTATIC, Opcodes.INVOKEINTERFACE -> Unit
                    else -> continue
                }

                if (node.owner in classFiles && classFiles.getValue(node.owner).editable) continue

                val key = "${node.owner} ${node.name} ${node.desc} ${node.opcode} ${file.javaName}"

                if (key !in newFunctions) {
                    val desc = if (node.opcode == Opcodes.INVOKEVIRTUAL || node.opcode == Opcodes.INVOKEINTERFACE) {
                        val ty = Type.getType(node.desc)
                        Type.getMethodDescriptor(ty.returnType, Type.getObjectType(node.owner), *ty.argumentTypes)
                    } else node.desc

                    newFunctions[key] = FunctionPrototype(
                        opcode = node.opcode,
                        owner = newOwner,
                        name = genObfName(),
                        desc = desc,
                        itf = node.itf,
                        targetClass = node.owner,
                        targetMethod = node.name,
                        targetDesc = node.desc
                    )
                }

                val func = newFunctions.getValue(key)
                node.opcode = Opcodes.INVOKESTATIC
                node.owner = func.owner
                node.name = func.name
                node.desc = func.desc
            }

            for (node in insn) {
                if (node !is MethodInsnNode || node.name != "<init>" || node.opcode != Opcodes.INVOKESPECIAL || node.itf) continue

                if (node.owner in classFiles && classFiles.getValue(node.owner).editable) continue

                val dup = node.previous ?: continue
                val new = dup.previous ?: continue
                if (dup.opcode != Opcodes.DUP || new.opcode != Opcodes.NEW || new !is TypeInsnNode) continue

                val key = "${node.owner} ${node.name} ${node.desc} ${node.opcode} ${file.javaName} NEW ${new.desc}"

                val ty = Type.getType(node.desc)
                val newDesc = Type.getMethodDescriptor(Type.getObjectType(new.desc), *ty.argumentTypes)

                if (key !in newFunctions) {
                    newFunctions[key] = FunctionPrototype(
                        opcode = node.opcode,
                        owner = newOwner,
                        name = genObfName(),
                        desc = newDesc,
                        itf = node.itf,
                        targetClass = node.owner,
                        targetMethod = node.name,
                        targetDesc = node.desc,
                        newClazz = new.desc,
                    )
                }

                insn.remove(new)
                insn.remove(dup)

                val func = newFunctions.getValue(key)
                node.opcode = Opcodes.INVOKESTATIC
                node.owner = func.owner
                node.name = func.name
                node.desc = func.desc
            }
        }
    }

    private fun createIndirectionClass(owner: String, methods: List<FunctionPrototype>) {
        val node = ClassNode()
        node.version = Opcodes.V1_8
        node.access = Opcodes.ACC_PUBLIC or Opcodes.ACC_SYNTHETIC
        node.name = owner
        node.signature = null
        node.superName = "java/lang/Object"

        methods.forEach { prototype ->
            val method = MethodNode(
                Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC,
                prototype.name,
                prototype.desc,
                null,
                arrayOf()
            )

            val argumentTypes = Type.getArgumentTypes(prototype.desc)
            var index = 0
            repeat(argumentTypes.size) { i ->
                val op = when (argumentTypes[i].sort) {
                    Type.INT -> Opcodes.ILOAD
                    Type.LONG -> Opcodes.LLOAD
                    Type.FLOAT -> Opcodes.FLOAD
                    Type.DOUBLE -> Opcodes.DLOAD
                    Type.BOOLEAN -> Opcodes.ILOAD
                    Type.CHAR -> Opcodes.ILOAD
                    Type.BYTE -> Opcodes.ILOAD
                    Type.SHORT -> Opcodes.ILOAD
                    else -> Opcodes.ALOAD
                }
                val inc = when (argumentTypes[i].sort) {
                    Type.INT -> 1
                    Type.LONG -> 2
                    Type.FLOAT -> 1
                    Type.DOUBLE -> 2
                    Type.BOOLEAN -> 1
                    Type.CHAR -> 1
                    Type.BYTE -> 1
                    Type.SHORT -> 1
                    else -> 1
                }
                method.instructions.add(VarInsnNode(op, index))
                index += inc
            }

            if (prototype.newClazz != null) {
                method.instructions.add(TypeInsnNode(Opcodes.NEW, prototype.newClazz))
                method.instructions.add(InsnNode(Opcodes.DUP))
            }

            method.instructions.add(
                MethodInsnNode(
                    prototype.opcode,
                    prototype.targetClass,
                    prototype.targetMethod,
                    prototype.targetDesc,
                    prototype.itf
                )
            )

            val returnTypeSort = if (prototype.newClazz != null) {
                Type.getObjectType(prototype.newClazz).sort
            } else {
                Type.getReturnType(prototype.targetDesc).sort
            }

            val op = when (returnTypeSort) {
                Type.VOID -> Opcodes.RETURN
                Type.INT -> Opcodes.IRETURN
                Type.LONG -> Opcodes.LRETURN
                Type.FLOAT -> Opcodes.FRETURN
                Type.DOUBLE -> Opcodes.DRETURN
                Type.BOOLEAN -> Opcodes.IRETURN
                Type.CHAR -> Opcodes.IRETURN
                Type.BYTE -> Opcodes.IRETURN
                Type.SHORT -> Opcodes.IRETURN
                else -> Opcodes.ARETURN
            }
            method.instructions.add(InsnNode(op))

            node.methods.add(method)
        }

        val classFile = ClassFile(null, node, true)
        exploreMethods(classFile)
        exploreFields(classFile)
        classFiles[owner] = classFile
    }

    /*private fun addInvokeDynamic(file: ClassFile) {
        if (!file.editable) return

        for (method in file.methods.values) {
            if (method.isCriticalForPerformance) continue
            val insn = method.methodNode.instructions

            for (node in insn.toArray()) {
                if (node !is MethodInsnNode) continue
                if (node.opcode != Opcodes.INVOKESTATIC) continue

                val handle = Opcodes.H_INVOKESTATIC

                val key = genObfName("")
                invokeMap[key] = "${handle},${node.owner},${node.name},${node.desc}"

                insn.insert(
                    node,
                    InvokeDynamicInsnNode(
                        "${settings.modId}$$key",
                        node.desc,
                        Handle(
                            handle,
                            "club/cpacket/drm/EncryptionUtils",
                            "decodeInvoke",
                            "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;"
                        )
                    )
                )
                insn.remove(node)
            }
        }
    }*/

    /* this isn't working anyway */
    /*private fun flowObf(node: ClassNode) {
        node.methods.forEach { method ->
            val analyzer = object : Analyzer<SourceValue>(SourceInterpreter()) {
                override fun newFrame(nLocals: Int, nStack: Int): Frame<SourceValue> =
                    Node<SourceValue>(nLocals, nStack)

                override fun newFrame(src: Frame<out SourceValue>): Frame<SourceValue> = Node(src)

                override fun newControlFlowEdge(src: Int, dst: Int) {
                    val s = frames[src] as Node<SourceValue>
                    s.successors.add(frames[dst] as Node<SourceValue>)
                }
            }

            analyzer.analyze(node.name, method)

            // Debugging (Comment out in production.)
            val frames = analyzer.frames.map { it as Node<SourceValue> }
            println(frames)
        }
    }*/

    private fun mangleStrings(file: ClassFile, offsetKey: Long) {
        if (!file.editable) return

        val encoder = Base64.getEncoder()

        fun encode(msg: String, keyString: String): String {
            val key = keyString.toCharArray()
            val bytes = ByteArray(msg.length)
            repeat(msg.length) { i ->
                val a = msg[i].toByte()
                val b = key[i % key.size].toByte()
                val c = key[(i + msg.length / 2) % key.size].toByte()
                val d = (msg.length % 256).toByte()
                val e = key[(31 + i * i) % key.size].toByte()
                val mod: Int = (-(d xor a) + b - c + e) % 256
                bytes[i] = (if (mod < 0) mod + 256 else mod).toByte()
            }
            return encoder.encodeToString(bytes)
        }

        fun toLong(str: String): Long {
            require(str.length == 4)
            return str[0].toLong() or (str[1].toLong() shl 16) or (str[2].toLong() shl 32) or (str[3].toLong() shl 48)
        }

        fun encodeLong(value: Long, key: Long, offset: Long): Long {
            return (value xor key) - offset
        }

        for (method in file.methods.values) {
            if (method.isCriticalForPerformance) continue
            val insn = method.methodNode.instructions

            for (node in insn) {
                if (node is LdcInsnNode && node.cst is String) {
                    val key = hexGenerator(8).first()
                    val value = node.cst as String

                    val pieceKey = Random.nextLong()
                    var checksum = file.obfName.replace('/', '.').hashCode().toLong()

                    val pieces = value.chunked(2).map { encodeLong(toLong(encode(it, key)), pieceKey, offsetKey) }

                    pieces.forEach { piece ->
                        checksum = checksum.inv() + piece
                        checksum = checksum xor (checksum shr 24)
                    }

                    checksum = checksum xor (checksum ushr 32)
                    val hashedKey = pieceKey xor checksum

                    insn.insert(node, InsnList().also {
                        it += LdcInsnNode(pieces.size)
                        it += IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_LONG)
                        pieces.forEachIndexed { index, piece ->
                            it += InsnNode(Opcodes.DUP)
                            it += LdcInsnNode(index)
                            it += LdcInsnNode(piece)
                            it += InsnNode(Opcodes.LASTORE)
                        }
                        it += LdcInsnNode(key)
                        it += LdcInsnNode(hashedKey)
                        it += MethodInsnNode(
                            Opcodes.INVOKESTATIC,
                            "club/cpacket/obfuscator/Strings",
                            "valueOf",
                            "([JLjava/lang/String;J)Ljava/lang/String;",
                            false
                        )
                    })
                    insn.remove(node)
                }
            }
        }
    }

    /*private fun encryptStrings(file: ClassFile) {
        if (!file.editable) return

        for (method in file.methods.values) {
            if (method.isCriticalForPerformance) continue
            val insn = method.methodNode.instructions

            for (node in insn) {
                if (node is LdcInsnNode && node.cst is String) {
                    val cst = node.cst as String
                    val value = Encryption.encryptString(settings.stringEncryptionKey, cst)
                    val stringValue = settings.modId + ":" + value

                    insn.insert(
                        node,
                        InsnList().also {
                            it += LdcInsnNode(stringValue)
                            it += MethodInsnNode(
                                Opcodes.INVOKESTATIC,
                                "club/cpacket/drm/EncryptionUtils",
                                "decodeString",
                                "(Ljava/lang/String;)Ljava/lang/String;",
                                false
                            )
                        }
                    )
                    insn.remove(node)
                }
            }
        }
    }*/

    private fun overrideValues(file: ClassFile) {
        val fields = settings.fieldValueOverrides[file.javaName] ?: return
        file.modified = true

        for ((field, newValue) in fields) {
            val classField = file.fields.values.find { it.name == field }
                ?: error("Field $field not found in: ${file.javaName}")

            classField.fieldNode.value = newValue
        }
    }

    private operator fun InsnList.plusAssign(node: AbstractInsnNode) {
        add(node)
    }

    private fun AbstractInsnNode.getConstant(): Any? {
        return when (opcode) {
            Opcodes.LDC -> (this as LdcInsnNode).cst
            Opcodes.ICONST_M1 -> -1
            Opcodes.ICONST_0 -> 0
            Opcodes.ICONST_1 -> 1
            Opcodes.ICONST_2 -> 2
            Opcodes.ICONST_3 -> 3
            Opcodes.ICONST_4 -> 4
            Opcodes.ICONST_5 -> 5
            Opcodes.FCONST_0 -> 0f
            Opcodes.FCONST_1 -> 1f
            Opcodes.FCONST_2 -> 2f
            Opcodes.DCONST_0 -> 0.0
            Opcodes.DCONST_1 -> 1.0
            Opcodes.LCONST_0 -> 0L
            Opcodes.LCONST_1 -> 1L
            Opcodes.SIPUSH -> (this as IntInsnNode).operand
            Opcodes.BIPUSH -> (this as IntInsnNode).operand
            else -> null
        }
    }

    private fun isSpecialMethod(method: String): Boolean {
        return method == "<init>"
                || method == "<clinit>"
                || method == "toString"
                || method == "hashCode"
                || method == "equals"
                || method == "clone"
                || method == "valueOf"
                || method.startsWith("lambda$")
    }

    private fun key(name: String, desc: String) = "$name: $desc"

    private fun genObfName(prefix: String = "1"): String {
        var hash: String = prefix

        when (settings.obfNameFormat) {
            Settings.ObfNameFormat.HEX -> {
                val bytes = 8
                do {
                    for (i in 0 until bytes * 2) {
                        hash += HEX_ARRAY[Random.nextBits(4) and 0x0F]
                    }
                } while (hash in generatedNames)
            }
            Settings.ObfNameFormat.SEQUENTIAL -> {
                var pos = generatedNames.size
                do {
                    hash += SEQUENTIAL_ARRAY[pos % SEQUENTIAL_ARRAY.size]
                    pos /= SEQUENTIAL_ARRAY.size
                } while (pos > 0)
            }
            Settings.ObfNameFormat.IL1J -> {
                val bytes = 18
                do {
                    for (i in 0 until bytes * 2) {
                        hash += IL1J_ARRAY[Random.nextInt(IL1J_ARRAY.size)]
                    }
                } while (hash in generatedNames)
            }
            Settings.ObfNameFormat.WHITESPACE -> {
                val bytes = 12
                do {
                    for (i in 0 until bytes * 2) {
                        hash += WHITESPACE_ARRAY[Random.nextInt(WHITESPACE_ARRAY.size)]
                    }
                } while (hash in generatedNames)
            }
            Settings.ObfNameFormat.BINARY -> {
                val bytes = 4
                do {
                    for (i in 0 until bytes * 8) {
                        hash += BINARY_ARRAY[Random.nextBits(1)]
                    }
                } while (hash in generatedNames)
            }
            Settings.ObfNameFormat.RANDOM -> {
                val bytes = 8
                do {
                    for (i in 0 until bytes) {
                        hash += RANDOM_ARRAY[Random.nextInt(RANDOM_ARRAY.size)]
                    }
                } while (hash in generatedNames)
            }
        }

        generatedNames += hash
        return hash
    }

    private fun mapClassName(name: String?): String? {
        if (name == null) return null
        return classFiles[name]?.obfName ?: name
    }

    private fun mapMethodName(owner: String, name: String, desc: String): String {
        val className = when {
            owner.startsWith("[") -> Type.getType(owner).elementType.internalName
            owner.startsWith("(") -> Type.getType(owner).returnType.internalName
            else -> owner
        }

        val key = key(name, desc)

        for (fileMeta in findDependencies(className)) {
            val newName = fileMeta.methods[key]
            if (newName != null) {
                return newName.obfName
            }
        }

        return name
    }

    private fun mapFieldName(owner: String, name: String, desc: String): String {
        val className = if (owner.startsWith("[")) {
            Type.getType(owner).elementType.internalName
        } else {
            if (isInternalName(owner)) owner else Type.getType(owner).internalName
        }

        val key = key(name, desc)

        for (fileMeta in findDependencies(className)) {
            val newName = fileMeta.fields[key]
            if (newName != null) {
                return newName.obfName
            }
        }

        return name
    }

    private fun findDependencies(className: String): List<ClassFile> {
        val current: ClassFile = classFiles[className] ?: return emptyList()
        val result = mutableListOf(current)

        for (dependency in current.dependencies) {
            result.addAll(findDependencies(dependency))
        }

        return result
    }

    private fun mapInternalName(name: String): String {
        return mapTypeDescriptor(Type.getObjectType(name)).internalName
    }

    private fun mapDescriptor(desc: String): String {
        return mapTypeDescriptor(Type.getType(desc)).descriptor
    }

    private fun mapTypeDescriptor(ty: Type): Type {
        if (ty.sort == Type.OBJECT) {
            return Type.getObjectType(mapClassName(ty.internalName))
        }

        if (ty.sort == Type.ARRAY) {
            val elem = mapDescriptor(ty.descriptor.substring(1))
            return Type.getObjectType("[$elem")
        }

        if (ty.sort == Type.METHOD) {
            val args = Array(ty.argumentTypes.size) {
                mapTypeDescriptor(ty.argumentTypes[it])
            }

            val returnTy = mapTypeDescriptor(ty.returnType)
            return Type.getType(Type.getMethodDescriptor(returnTy, *args))
        }

        return ty
    }

    private fun isInternalName(name: String): Boolean = name.isEmpty() || when (name[0]) {
        '[' -> false
        'V' -> false
        'Z' -> false
        'C' -> false
        'B' -> false
        'S' -> false
        'I' -> false
        'F' -> false
        'J' -> false
        'D' -> false
        'L' -> false
        '(' -> false
        else -> true
    }

    fun exportMappings(target: File) {
        val builder = StringBuilder()

        for (classFile in classFiles.values.filter { it.editable }) {
            if (settings.enableClassObf && classFile.obfName != classFile.name) {
                builder.append("CLASS  '")
                builder.append(classFile.obfName)
                builder.append("' ")
                builder.append(classFile.name)
                builder.appendLine()
            }

            for ((_, classMethod) in classFile.methods) {
                if (settings.enableMethodObf && classMethod.obfName != classMethod.name) {
                    builder.append("METHOD '")
                    builder.append(classMethod.obfName)
                    builder.append("' ")
                    builder.append(classFile.name)
                    builder.append(" ")
                    builder.append(classMethod.name)
                    builder.append(" ")
                    builder.append(classMethod.desc)
                    builder.appendLine()
                }

                if (settings.enableLocalObf) {
                    for ((name, obfName) in classMethod.locals) {
                        if (name == obfName) continue

                        builder.append("LOCAL  '")
                        builder.append(obfName)
                        builder.append("' ")
                        builder.append(classFile.name)
                        builder.append(" ")
                        builder.append(classMethod.name)
                        builder.append(" ")
                        builder.append(classMethod.desc)
                        builder.append(" ")
                        builder.append(name)
                        builder.appendLine()
                    }
                }
            }

            if (settings.enableFieldObf) {
                for ((_, classField) in classFile.fields) {
                    if (classField.obfName == classField.name) continue

                    builder.append("FIELD  '")
                    builder.append(classField.obfName)
                    builder.append("' ")
                    builder.append(classFile.name)
                    builder.append(" ")
                    builder.append(classField.name)
                    builder.append(" ")
                    builder.append(classField.desc)
                    builder.appendLine()
                }
            }
        }

        target.writeText(builder.toString())
    }

    companion object {
        fun murmurOAAT32(text: String): Int {
            val bytes = text.toByteArray(Charsets.UTF_8)
            var h = 3323198485.toInt()

            bytes.forEach {
                h = h xor (it.toInt() and 0xFF)
                h *= 0x5bd1e995
                h = h xor (h ushr 15)
            }
            return h
        }

        fun murmurOAAT64(text: String): Long {
            val bytes = text.toByteArray(Charsets.UTF_8)
            var h = 525201411107845655

            bytes.forEach {
                h = h xor (it.toLong() and 0xFF)
                h *= 0x5bd1e9955bd1e995
                h = h xor (h ushr 47)
            }
            return h
        }
    }

    private class ClassFile(
        val originalFile: File?,
        var classNode: ClassNode,
        var editable: Boolean
    ) {
        val name: String = classNode.name
        val javaName: String = name.replace('/', '.')
        val superClass: String = classNode.superName ?: "java/lang/Object"
        val dependencies: Set<String> = (classNode.interfaces + superClass).filter { it != "java/lang/Object" }.toSet()
        var obfName: String = name
        val methods = mutableMapOf<String, ClassMethod>()
        val fields = mutableMapOf<String, ClassField>()
        var modified: Boolean = false
        val seedInt: Int = Random.nextInt(0x7FFFFFFF)
        val seedLong: Long = Random.nextLong(0x7FFFFFFF)
    }

    private class ClassMethod(val methodNode: MethodNode) {
        val name: String = methodNode.name
        val desc: String = methodNode.desc
        var obfName: String = name
        val locals: MutableMap<String, String> = mutableMapOf()
        var isCriticalForPerformance: Boolean = run {
            // Ignore methods with annotation @CriticalPerformance.
            val hasAnnotation = methodNode.visibleAnnotations?.any {
                it.desc.contains("CriticalPerformance", true)
            } ?: false

            // Ignore methods with annotation @CriticalPerformance on any parameter. [Lambdas]
            val hasParamAnnotation = methodNode.visibleParameterAnnotations?.any { param ->
                param?.any { it.desc.contains("CriticalPerformance", true) } ?: false
            } ?: false

            if (hasParamAnnotation) {
                println("works")
            }

            hasAnnotation || hasParamAnnotation
        }
    }

    private class ClassField(val fieldNode: FieldNode) {
        val name: String = fieldNode.name
        val desc: String = fieldNode.desc
        var obfName: String = name
    }

    data class FunctionPrototype(
        val opcode: Int,
        val owner: String,
        val name: String,
        val desc: String,
        val itf: Boolean,
        val targetClass: String,
        val targetMethod: String,
        val targetDesc: String,
        val newClazz: String? = null,
    )
}

fun hexGenerator(bytes: Int): Sequence<String> {
    return sequence {
        val generatedHashes = mutableSetOf<String>()
        var hash: String
        while (true) {
            do {
                hash = ""
                for (i in 0 until bytes) {
                    val num = Random.nextBits(8)
                    hash += HEX_ARRAY[num ushr 4]
                    hash += HEX_ARRAY[num and 0x0F]
                }
            } while (hash in generatedHashes)

            generatedHashes += hash
            yield(hash)
        }
    }
}

fun main() {
    val b = Obfuscator.murmurOAAT32("13875C6A8C0C2BAE7")
    println(b)
}