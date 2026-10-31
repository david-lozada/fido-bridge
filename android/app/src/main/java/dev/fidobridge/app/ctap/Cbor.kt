package dev.fidobridge.app.ctap

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

/** Minimal CTAP-oriented CBOR codec (maps, arrays, ints, bytes, text, bool). */
sealed class CborValue {
    data class Integer(val value: Long) : CborValue()
    data class Bytes(val value: ByteArray) : CborValue() {
        override fun equals(other: Any?) = other is Bytes && value.contentEquals(other.value)
        override fun hashCode() = value.contentHashCode()
    }
    data class Text(val value: String) : CborValue()
    data class Array(val value: List<CborValue>) : CborValue()
    data class Map(val value: LinkedHashMap<CborValue, CborValue>) : CborValue()
    data class Bool(val value: Boolean) : CborValue()
    data object Null : CborValue()
}

object Cbor {
    fun encode(value: CborValue): ByteArray {
        val out = ByteArrayOutputStream()
        write(out, value)
        return out.toByteArray()
    }

    fun decode(data: ByteArray): CborValue {
        val inn = ByteArrayInputStream(data)
        return read(inn)
    }

    private fun write(out: ByteArrayOutputStream, value: CborValue) {
        when (value) {
            is CborValue.Integer -> writeInt(out, value.value)
            is CborValue.Bytes -> {
                writeHeader(out, 2, value.value.size.toLong())
                out.write(value.value)
            }
            is CborValue.Text -> {
                val b = value.value.toByteArray(Charsets.UTF_8)
                writeHeader(out, 3, b.size.toLong())
                out.write(b)
            }
            is CborValue.Array -> {
                writeHeader(out, 4, value.value.size.toLong())
                value.value.forEach { write(out, it) }
            }
            is CborValue.Map -> {
                writeHeader(out, 5, value.value.size.toLong())
                for ((k, v) in value.value) {
                    write(out, k)
                    write(out, v)
                }
            }
            is CborValue.Bool -> out.write(if (value.value) 0xf5 else 0xf4)
            CborValue.Null -> out.write(0xf6)
        }
    }

    private fun writeInt(out: ByteArrayOutputStream, value: Long) {
        if (value >= 0) {
            writeHeader(out, 0, value)
        } else {
            writeHeader(out, 1, -1L - value)
        }
    }

    private fun writeHeader(out: ByteArrayOutputStream, major: Int, arg: Long) {
        val mt = major shl 5
        when {
            arg < 24 -> out.write(mt or arg.toInt())
            arg < 0x100 -> {
                out.write(mt or 24)
                out.write(arg.toInt())
            }
            arg < 0x10000 -> {
                out.write(mt or 25)
                out.write((arg shr 8).toInt())
                out.write(arg.toInt())
            }
            arg < 0x100000000L -> {
                out.write(mt or 26)
                out.write((arg shr 24).toInt())
                out.write((arg shr 16).toInt())
                out.write((arg shr 8).toInt())
                out.write(arg.toInt())
            }
            else -> {
                out.write(mt or 27)
                for (i in 7 downTo 0) out.write((arg shr (8 * i)).toInt())
            }
        }
    }

    private fun read(inn: ByteArrayInputStream): CborValue {
        val ib = inn.read()
        if (ib < 0) error("unexpected end")
        val major = ib shr 5
        val ai = ib and 0x1f
        val arg = readArg(inn, ai)
        return when (major) {
            0 -> CborValue.Integer(arg)
            1 -> CborValue.Integer(-1 - arg)
            2 -> CborValue.Bytes(readBytes(inn, arg.toInt()))
            3 -> CborValue.Text(String(readBytes(inn, arg.toInt()), Charsets.UTF_8))
            4 -> CborValue.Array((0 until arg.toInt()).map { read(inn) })
            5 -> {
                val map = LinkedHashMap<CborValue, CborValue>()
                repeat(arg.toInt()) {
                    val k = read(inn)
                    val v = read(inn)
                    map[k] = v
                }
                CborValue.Map(map)
            }
            7 -> when (ai) {
                20 -> CborValue.Bool(false)
                21 -> CborValue.Bool(true)
                22 -> CborValue.Null
                else -> error("unsupported simple $ai")
            }
            else -> error("unsupported major $major")
        }
    }

    private fun readArg(inn: ByteArrayInputStream, ai: Int): Long {
        return when {
            ai < 24 -> ai.toLong()
            ai == 24 -> inn.read().toLong()
            ai == 25 -> ((inn.read() shl 8) or inn.read()).toLong()
            ai == 26 -> {
                var v = 0L
                repeat(4) { v = (v shl 8) or (inn.read().toLong() and 0xff) }
                v
            }
            ai == 27 -> {
                var v = 0L
                repeat(8) { v = (v shl 8) or (inn.read().toLong() and 0xff) }
                v
            }
            else -> error("indefinite not supported")
        }
    }

    private fun readBytes(inn: ByteArrayInputStream, n: Int): ByteArray {
        val b = ByteArray(n)
        var off = 0
        while (off < n) {
            val r = inn.read(b, off, n - off)
            if (r < 0) error("short read")
            off += r
        }
        return b
    }
}

fun CborValue.asMap(): LinkedHashMap<CborValue, CborValue>? =
    (this as? CborValue.Map)?.value

fun CborValue.Map.getInt(key: Long): Long? =
    (value[CborValue.Integer(key)] as? CborValue.Integer)?.value

fun CborValue.Map.getBytes(key: Long): ByteArray? =
    (value[CborValue.Integer(key)] as? CborValue.Bytes)?.value

fun CborValue.Map.getText(key: Long): String? =
    (value[CborValue.Integer(key)] as? CborValue.Text)?.value

fun CborValue.Map.getMap(key: Long): CborValue.Map? =
    value[CborValue.Integer(key)] as? CborValue.Map

fun CborValue.Map.getArray(key: Long): List<CborValue>? =
    (value[CborValue.Integer(key)] as? CborValue.Array)?.value

fun CborValue.Map.getTextKey(key: String): CborValue? =
    value[CborValue.Text(key)]
