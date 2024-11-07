import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class PairFinder {
    private static final int DELTA_P = 0x0BA2; // ΔP as a 16-bit hexadecimal integer

    public static void main(String[] args) {
        String inputFilename = "nicolas2_secret_plaintexts.txt";         // Input file with 16-bit hexadecimal strings
        String outputFilename = "matching_pairs.txt"; // Output file for matching pairs

        List<String> matchingPairs = findDifferentialPairs(inputFilename);

        // Write matching pairs to the output file
        if (matchingPairs.isEmpty()) {
            System.out.println("No pairs found with the specified difference.");
        } else {
            writePairsToFile(matchingPairs, outputFilename);
            System.out.println("Matching pairs have been written to " + outputFilename);
        }
    }

    /**
     * Reads 16-bit hexadecimal strings from a file and finds pairs with a difference of ΔP.
     * @param filename The file to read from
     * @return List of formatted strings representing matching pairs
     */
    public static List<String> findDifferentialPairs(String filename) {
        List<String> lines = new ArrayList<>();
        List<String> matchingPairs = new ArrayList<>();

        // Read all lines from the file into the list
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.matches("[0-9A-Fa-f]{4}")) {  // Check if the line is a valid 4-character hex string
                    lines.add(line);
                } else {
                    System.out.println("Skipping invalid line: " + line);
                }
            }
        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
            return matchingPairs;
        }

        // Compare each line with every other line to find pairs with the specified difference
        for (int i = 0; i < lines.size(); i++) {
            int num1 = Integer.parseInt(lines.get(i), 16);  // Convert hex string to integer
            for (int j = i + 1; j < lines.size(); j++) {
                int num2 = Integer.parseInt(lines.get(j), 16);

                // Check if the difference between num1 and num2 matches ΔP
                if ((num1 ^ num2) == DELTA_P) {
                    matchingPairs.add("Pair: " + lines.get(i) + " and " + lines.get(j));
                }
            }
        }

        return matchingPairs;
    }

    /**
     * Writes matching pairs to an output file.
     * @param pairs List of pairs to write
     * @param filename The file to write the pairs to
     */
    public static void writePairsToFile(List<String> pairs, String filename) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) {
            for (String pair : pairs) {
                writer.write(pair);
                writer.newLine();
            }
        } catch (IOException e) {
            System.err.println("Error writing to file: " + e.getMessage());
        }
    }
}
