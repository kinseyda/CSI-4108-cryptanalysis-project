import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
public class differentialCharacteristic {
 
    public static void main(String[] args) {
 
        int[][] estimatedValue = biggestTableValue(getDifferenceDistributionTable());
        String keyChance = "";
        String binairyValue = "0000101100000000"; // Default value
        if (args.length > 0) {
            binairyValue = args[0]; // Use the provided binary value
        }
        System.out.println("Input binary value: " + binairyValue);
         
        //Round 1
        String[] hexValue = convertHexStringToArray(binairyValue);
        String[] returnedValue = sBox(hexValue, estimatedValue, keyChance);
        String newInput = formatHexString(returnedValue[0]);
        keyChance = returnedValue[1];
        String[][] tempArray = permute(newInput); 
        binairyValue = appendArrayItems(tempArray);
         
        //Round 2
        hexValue = convertHexStringToArray(binairyValue); 
        returnedValue = sBox(hexValue, estimatedValue, keyChance);
        newInput = formatHexString(returnedValue[0]);
        keyChance = returnedValue[1];
        tempArray = permute(newInput); 
        binairyValue = appendArrayItems(tempArray); 

        //Round 3
        hexValue = convertHexStringToArray(binairyValue);
        returnedValue = sBox(hexValue, estimatedValue, keyChance);
        newInput = formatHexString(returnedValue[0]);
        keyChance = returnedValue[1]; 

        //Finished product
        
        tempArray = permute(newInput); 
        binairyValue = appendArrayItems(tempArray);
        newInput = formatHexString(binairyValue);
        System.out.println();
        System.out.println("Output binary value: " + newInput);

        // This part of the code is used to calculate the probability of the difference pair
        String[] numbers = keyChance.split("\\+");
        double result = 1.0;

        for (String num : numbers) {
            if (!num.isEmpty()) { // Check to skip any empty string (e.g., trailing "+")
                double value = Double.parseDouble(num);
                value = value / 16; // Divide by 16
                result *= value; // Multiply with the running product
            }
        }

        System.out.println("Result: " + result);
    }

    /**
     * This method is used to format the binary output in groups of four bits separated by commas
     * @param value
     * @return
     */
    public static String formatBinary(int value) {
        StringBuilder binaryString = new StringBuilder(Integer.toBinaryString(value));
        
        // Pad the binary string with leading zeros to make it 16 bits
        while (binaryString.length() < 16) {
            binaryString.insert(0, '0');
        }

        // Add commas to format in groups of four
        StringBuilder formattedString = new StringBuilder();
        for (int i = 0; i < binaryString.length(); i++) {
            formattedString.append(binaryString.charAt(i));
            if ((i + 1) % 4 == 0 && i != binaryString.length() - 1) {
                formattedString.append(','); // Add a comma after every four bits
            }
        }

        return formattedString.toString();
    }

    public static String[][] arrayCreator(String input) {
        String[] splitArray = input.split(",");

        // Step 2: Create a 2D array to hold the results
        String[][] resultArray = new String[splitArray.length][];
        
        // Step 3: Fill the 2D array with the split values
        for (int i = 0; i < splitArray.length; i++) {
            resultArray[i] = splitArray[i].split(""); // Split each string into an array of characters
        }

        // Step 4: Print the result
        System.out.print("Input Array: ");
        print2DArray(resultArray);
        return resultArray;
    }

    public static void print2DArray(String[][] arr) {
        System.out.println("[");
        for (String[] row : arr) {
            System.out.print("  [");
            for (int j = 0; j < row.length; j++) {
                System.out.print(row[j]);
                if (j < row.length - 1) {
                    System.out.print(", ");
                }
            }
            System.out.println("],");
        }
        System.out.println("]");
    }

    /**
     * This method is used to format the hexadecimal string in groups of four characters separated by commas
     * @param hex
     * @return
     */
    public static String formatHexString(String hex) {
        // Use StringBuilder for efficient string manipulation
        StringBuilder formatted = new StringBuilder();

        // Process the string in chunks of four characters
        for (int i = 0; i < hex.length(); i += 4) {
            // Check if it's the last chunk and if it needs a comma
            if (i + 4 < hex.length()) {
                formatted.append(hex, i, i + 4).append(",");
            } else {
                formatted.append(hex.substring(i)); // Append remaining characters without comma
            }
        }
 
        return formatted.toString();
    }

    public static String[] convertHexStringToArray(String hex) {
        String[] hexArray = new String[4]; // 2D array with one column

        for (int i = 0; i < hex.length(); i += 4) {
            // Get the substring of 4 characters, or the remaining characters
            
            String group = hex.substring(i, Math.min(i + 4, hex.length()));
            hexArray[i / 4] = group; // Store it in the array
            //System.out.println(hexArray[i/4]);
        }

        return hexArray;
    }

    public static String appendArrayItems(String[][] array) {
        StringBuilder resultBuilder = new StringBuilder(); // Use StringBuilder for efficiency

        // Iterate through each row of the 2D array
        for (String[] row : array) {
            // Iterate through each item in the row
            for (String item : row) {
                resultBuilder.append(item).append(""); // Append the item and a space
            }
        }

        // Convert StringBuilder to String and trim any trailing spaces
        return resultBuilder.toString().trim();
    }

    public static String[][] permute(String newInput){
        System.out.println("Input value: " + newInput);
        String[][] array = arrayCreator(newInput);
        String[][] tempArray = new String[array[0].length][array.length];
        
        System.out.print("Output Array after permutation: ");
        for (int i = 0; i < array.length; i++) {
            for (int j = 0; j < array[i].length; j++) {
                if (array[i][j].contains("1")) {
                    tempArray[j][i] = "1"; // Move 1 from array[i][j] to tempArray[j][i]
                }
                else {
                    tempArray[j][i] = "0"; // Move 0 from array[i][j] to tempArray[j][i]
                }
            }
        
        }
        print2DArray(tempArray);
        return tempArray;
    }

     

    private static String[] sBox (String array[], int[][] estimatedValue, String keyChance){
        String[] tempArray = new String[4];
        String temp = "";
        for (int i = 0; i< 4; i++){
            String[] split = array[i].split("");
            int decimalNumber = Integer.parseInt(split[0])*8 + Integer.parseInt(split[1])*4 + Integer.parseInt(split[2])*2 + Integer.parseInt(split[3]);
            System.out.println("Sbox"+i+" will go from " +decimalNumber+" to "+estimatedValue[decimalNumber][1]);

            tempArray[i] = String.format("%4s", Integer.toBinaryString(estimatedValue[decimalNumber][1])).replace(' ', '0');
            temp += tempArray[i];

            if(estimatedValue[decimalNumber][0] != 16){ 
                keyChance += estimatedValue[decimalNumber][0]+"+"; 
            }
            tempArray[0] = temp;
            tempArray[1] = String.valueOf(keyChance);

        }
        return tempArray;
 

    }

    /**Used to get difference distribution table from a file
     * 
     * @return a array with the difference distribution table
     */
    public static int[][] getDifferenceDistributionTable() {
            String filePath = "difference_distribution_table.txt"; // Update this with your file path
                    int[][] array = new int[16][16]; // 2D array to hold the values
            
                    try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
                        String line;
                        int row = 0;
            
                        while ((line = br.readLine()) != null && row < 16) {
                            // Split the line by tabs or spaces (regex to account for multiple spaces)
                            String[] numbers = line.trim().split("\\s+");
                            
                            for (int col = 0; col < 16; col++) {
                                // Parse the number and store it in the array
                                array[row][col] = Integer.parseInt(numbers[col]);
                            }
                            row++; // Move to the next row
                        }
                    } catch (IOException e) {
                        e.printStackTrace(); // Handle exceptions
                    }
            
                    // Optional: Print the resulting 2D array to verify
                    //printArray(array);
                    //System.out.println(array[3][2]);
                    return array;
                }

            /*private static void printArray(int[][] arr) {
                for (int[] row : arr) {
                    for (int num : row) {
                        System.out.print(num + "\t");
                    }
                    System.out.println();
                }
            }*/

            /**
             * This method is usefull find what is the estimated in the box
             * in the profs notes B -> 2, 4 -> 6, 2->5. All these have in common is that they are the highest value in the table for the row
             * 
             * @param array finds the biggest value in a 2D array
             * @return a 2D array with the biggest value and its index
             */
            public static int[][] biggestTableValue(int[][] array) {
                int[][] valueArray = new int[array.length][2]; // Array to store max value and index
                for (int i = 0; i < array.length; i++) {
                      // Get the sub-array
                    int maxIndex = 0; // Start with the first index
                    int maxValue = array[i][0]; // Start with the first value
                    
                    for (int j = 1; j < array[i].length; j++) {
                        if (array[i][j] > maxValue) {
                            maxValue = array[i][j];
                            maxIndex = j; // Update index when a new max is found
                        }
                    }
                    valueArray[i][0] = maxValue;
                    valueArray[i][1] = maxIndex;
                    // Print the results for this sub-array
                    //System.out.println("Sub-array " + i + ": Max Value = " + maxValue + ", Index = " + maxIndex);
                } 
                return valueArray;
            } 
}

 