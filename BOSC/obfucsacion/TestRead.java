import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class TestRead {
    public static void main(String[] args) throws Exception {
        String[] paths = {
            "/Users/gaman/Desktop/BOSC/inputs/wormhole_hex_valid/ethereum_0xAaDA05BD399372f0b0463744C09113c137636f6a.hex",
            "/Users/gaman/Desktop/BOSC/inputs/axelar_hex_valid/linea-sepolia_0xB5FB4BE02232B1bBA4dC8f81dc24C26980dE9e3C.hex"
        };
        
        for (String path : paths) {
            try {
                System.out.println("\n--- Testing: " + path.substring(path.lastIndexOf('/') + 1) + " ---");
                List<String> lines = Files.readAllLines(Paths.get(path), StandardCharsets.UTF_8);
                System.out.println("Lines read: " + lines.size());
                if (lines.size() > 0) {
                    System.out.println("First line length: " + lines.get(0).length());
                }
            } catch (Exception e) {
                System.out.println("ERROR: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }
}
