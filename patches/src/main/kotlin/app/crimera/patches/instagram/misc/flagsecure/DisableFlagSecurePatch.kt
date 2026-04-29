/*
 * Copyright (C) 2026 piko <https://github.com/crimera/piko>
 *
 * This file is part of piko.
 *
 * Any modifications, derivatives, or substantial rewrites of this file
 * must retain this copyright notice and the piko attribution
 * in the source code and version control history.
 */
package app.crimera.patches.instagram.misc.flagsecure

import app.crimera.patches.instagram.links.interceptUriPatch
import app.crimera.patches.instagram.misc.settings.settingsPatch
import app.crimera.patches.instagram.utils.Constants
import app.crimera.patches.instagram.utils.Constants.COMPATIBILITY_INSTAGRAM
import app.morphe.patcher.Fingerprint
import app.morphe.patcher.extensions.InstructionExtensions.addInstructionsWithLabels
import app.morphe.patcher.extensions.InstructionExtensions.getInstruction
import app.morphe.patcher.extensions.InstructionExtensions.instructions
import app.morphe.patcher.patch.bytecodePatch
import app.morphe.patcher.util.smali.ExternalLabel
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction

internal object FlagSecureManagerFingerprint : Fingerprint(
    strings = listOf("Inconsistency in window FLAG_SECURE state detected!"),
)

@Suppress("unused")
val disableFlagSecurePatch =
    bytecodePatch(
        name = "Disable FLAG_SECURE",
        description = "Allows screenshots and screen recording on protected screens like DMs and view-once media.",
    ) {
        dependsOn(settingsPatch, interceptUriPatch)
        compatibleWith(COMPATIBILITY_INSTAGRAM)

        execute {
            FlagSecureManagerFingerprint.classDef.methods.forEach { method ->
                method.apply {
                    // Find all invoke-virtual instructions that call Window.setFlags
                    val setFlagsInstructions =
                        instructions.filter {
                            it.opcode == Opcode.INVOKE_VIRTUAL &&
                                it is ReferenceInstruction &&
                                it.reference.toString().contains("Landroid/view/Window;->setFlags(II)V")
                        }.toList()

                    // Iterate in reverse so index insertions don't shift upcoming targets
                    setFlagsInstructions.reversed().forEach { instruction ->
                        val index = instruction.location.index
                        val skipTarget = getInstruction(index + 1)

                        // Inject the condition and pass the ExternalLabel in the EXACT SAME call
                        addInstructionsWithLabels(
                            index,
                            """
                            ${Constants.PREF_CALL_DESCRIPTOR}->disableScreenshotDetection()Z
                            move-result v0
                            if-eqz v0, :skip_setflags
                            """.trimIndent(),
                            ExternalLabel("skip_setflags", skipTarget),
                        )
                    }
                }
            }
        }
    }

