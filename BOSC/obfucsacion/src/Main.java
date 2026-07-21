import utils.ArrayToCodeString;
import utils.ByteCodeOutput;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static obfuscationmethods.FalseBranchConfuse.*;
import static obfuscationmethods.FlowerInstructionConfuse.InsertFlowerInstructions;
import static obfuscationmethods.FlowerInstructionConfuse.constructFlowerInstructions;
import static obfuscationmethods.IncompleteInstructionsConfuse.InsertIncompleteInstructions;
import static obfuscationmethods.InstructionOrderRearrangeConfuse.OrderRearrange;
import static obfuscationmethods.InstructionOrderRearrangeConfuse.constructIndependentInstruction;
import static utils.ByteCodeCleanAndRecovry.byteCodeClean;
import static utils.ByteCodeCleanAndRecovry.byteCodeRecovery;
import static utils.ByteCodeInput.readFileContent;
import static utils.CodeStingToArray.ToArray;
import static utils.FindJumpAndChangeBValue.findDupicateInArray;
import static utils.InsertIndex.insertIndex;

/**
 * test class
 * The overall process is as follows:
 * 1. Input: solidity bytecode file, suffixed with .hex
 * 2. Bytecode cleaning: remove the meaningless part, leaving the part that is really related to the program logic for subsequent confusion
 * 3. Bytecode obfuscation: Before obfuscation, according to different bytecode obfuscation techniques, it is necessary to locate the place that can be obfuscated, and then obfuscate the cleaned bytecode in turn
 * 4. Restore bytecode: return the previously removed bytecode part
 * 5. Output: The obfuscated bytecode file, renamed to "current time+confusedCode.hex".
 */
public class Main {
    //1.get the bytecode file from the file
    public static void main(String[] args) throws Exception {
            Path projectRoot = Paths.get(System.getProperty("user.dir"));
            Path defaultInput = projectRoot.resolve("src/dataset/example.hex");
            Path defaultOutputDir = projectRoot.resolve("output");

            String inputPath = defaultInput.toString();
            String outputDir = defaultOutputDir.toString();
            boolean outputEntireBytecode = false;

            for (int i = 0; i < args.length; i++) {
                if ("--entire".equals(args[i])) {
                    outputEntireBytecode = true;
                } else if (inputPath.equals(defaultInput.toString())) {
                    inputPath = args[i];
                } else if (outputDir.equals(defaultOutputDir.toString())) {
                    outputDir = args[i];
                }
            }

            Path inputFile = Paths.get(inputPath);
            String filename = inputFile.getFileName().toString();

            long start = System.currentTimeMillis();
            List bytecodeFile = readFileContent(inputFile.toString());
            System.out.println("read bytecode file……");
            if (bytecodeFile.size() == 0){
                System.out.println("read failed！");
            }else {
                System.out.println("read successed！");
            }

            //2.Convert the bytecode file to an array of strings
            //ToArray(bytecodeFile.get(0));
            System.out.println("Converting the bytecode file to an array of strings……");
            Object o = bytecodeFile.get(0);

            char ss2[] = String.valueOf(o).toCharArray();

            String[] bytecode = ToArray(String.valueOf(o));
            System.out.println("The bytecode file was successfully converted to a string array!");

            //3.clean bytecode
            System.out.println("cleaning bytecode……");
            String[] cleanedBytecode = byteCodeClean(bytecode);
            System.out.println("clean bytecode done！");
            long end = System.currentTimeMillis();
            System.out.println("preprocessing time："+ (end - start) + "ms");

            //4.Incomplete Instruction Obfuscation
            System.out.println("Incomplete instruction obfuscation in progress……");
            long s1 = System.currentTimeMillis();
            String[] bytecode1 = InsertIncompleteInstructions(cleanedBytecode);
            long e1 = System.currentTimeMillis();
            System.out.println("Completed incomplete instruction obfuscation technique！"
                    + "execution time："+ (e1 - s1) + "ms");

            //5. False branch obfuscation
            //5.1 Determine if there is a jump
            System.out.println("Fake branch obfuscation in progress……");
            long s22 = System.currentTimeMillis();
            if (isExistJump(bytecode1)==-1){
                //5.2 If not, construct true and false instructions
                System.out.println("Without the jump instruction, the true and false paths will be constructed.");
                InsertJumpi(bytecode1, insertIndex(bytecode1));
            }else {
                System.out.println("There is a jump instruction, change it to a true and false " +
                        "instruction with a conditional jump");
                //5.2 If there is, it is changed to a true and false instruction with a conditional jump
                List<Integer> dupicateInArray1 = findDupicateInArray(bytecode1, 0);
                if(dupicateInArray1.size() == 0){
                        System.out.println("It should not be inserted here and will be skipped. . .");
                }else {
                changeToJumpi(bytecode1, dupicateInArray1.get(0));
                }

            }
            long e2 = System.currentTimeMillis();
            System.out.println("Completed fake branch obfuscation technique."+ "execution time："+ (e2 - s22) + "ms");

            //5.flower instruction obfuscation technique
            System.out.println("Flower instruction obfuscation technology in progress...");
            long s3 = System.currentTimeMillis();
            String flowerInstruction = constructFlowerInstructions();
            String[] bytecode2 = InsertFlowerInstructions(bytecode1, flowerInstruction);
            long e3 = System.currentTimeMillis();
            System.out.println("Flower instruction obfuscation completed."+ "execution time："+ (e3 - s3) + "ms");

            //6.Instruction Order Rearrangement Obfuscation Technology
            System.out.println("Instruction order reordering obfuscation in progress...");
            long s4 = System.currentTimeMillis();
            String[] IndependentInstruction = constructIndependentInstruction();
            String[] bytecode3 = OrderRearrange(bytecode2, IndependentInstruction);
            long e4 = System.currentTimeMillis();
            System.out.println("Completed instruction order reordering obfuscation technology..."
                    + "execution time："+ (e3 - s3) + "ms");

            //7.Obfuscation complete, bytecode recovery
            System.out.println("Bytecode recovery in progress……");
            String[] bytecode4 = byteCodeRecovery(bytecode, bytecode3);
            System.out.println("Bytecode recovery completed……");

            Date date = new Date();
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH：mm：ss");
            String timestamp = dateFormat.format(date);
            System.out.println(timestamp);

            System.out.println("Outputting runtime bytecode to destination folder...");
            String runtimeObfuscatedBytecode = ArrayToCodeString.toString(bytecode3);
            String runtimeFileName = Paths.get(outputDir, timestamp + "runtimeobfuscated" + filename).toString();
            ByteCodeOutput.createFile(runtimeFileName, runtimeObfuscatedBytecode);

            if (outputEntireBytecode) {
                System.out.println("Converting string array to string form……");
                String entireObfuscatedBytecode = ArrayToCodeString.toString(bytecode4);
                System.out.println("Completed string array to string form……");
                System.out.println("outputting entire bytecode to destination folder……");
                String entireFileName = Paths.get(outputDir, timestamp + "entireobfuscated" + filename).toString();
                ByteCodeOutput.createFile(entireFileName, entireObfuscatedBytecode);
            }

    }

}
