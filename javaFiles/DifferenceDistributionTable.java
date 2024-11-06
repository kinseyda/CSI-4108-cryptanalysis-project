
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

public class DifferenceDistributionTable {
    // Define the S-box as a 16-element array (for a 4-bit input/output S-box)
    private static final int[] SBOX = {
        //0 goes to E, 1 goes to 4, etc...
        0x0, 0xF, 0x7, 0x4, 0xE, 0x2, 0xD, 0x1,
        0xA, 0x6, 0xC, 0xB, 0x9, 0x5, 0x3, 0x8
    };
 
    // Initialize the DDT as a 16x16 array
    private static final int[][] DDT = new int[16][16];

    public static void main(String[] args) {
        fillDDT();
        printDDTToFile();
    }

    // Method to fill the Difference Distribution Table (DDT)
    private static void fillDDT() {
        // Loop through all possible input differences ΔX (0 to 15)
        for (int deltaX = 0; deltaX < 16; deltaX++) {
            // For each ΔX, test all possible values of X1
            for (int x1 = 0; x1 < 16; x1++) {
                int x2 = x1 ^ deltaX;  // Calculate X2 as X1 ⊕ ΔX
                int y1 = SBOX[x1];     // S-box output for X1
                int y2 = SBOX[x2];     // S-box output for X2
                int deltaY = y1 ^ y2;  // Calculate ΔY as Y1 ⊕ Y2

                // Increment the count for this (ΔX, ΔY) pair in the DDT
                DDT[deltaX][deltaY]++;
            }
        }
    }

    // Method to print the DDT to a file
    private static void printDDTToFile() {
        try (PrintWriter writer = new PrintWriter(new FileWriter("DDT_Output.txt"))) {
            writer.println("Difference Distribution Table (DDT):");
            writer.println("ΔX \\ ΔY |  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F");
            writer.println("--------------------------------------------------------");

            for (int deltaX = 0; deltaX < 16; deltaX++) {
                writer.printf("   %X     |", deltaX);
                for (int deltaY = 0; deltaY < 16; deltaY++) {
                    writer.printf(" %2d", DDT[deltaX][deltaY]);
                }
                writer.println();
            }
            System.out.println("DDT written to DDT_Output.txt");
        } catch (IOException e) {
            System.out.println("An error occurred while writing to file.");
            e.printStackTrace();
        }
    }
}
