package Implementation.code;

import java.awt.*;
import java.awt.event.*;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ThreatActorApp extends Frame {
    private TextField searchField;
    private TextArea resultArea;
    private Label statusLabel;
    private Button searchButton;
    private Button loadAllButton;

    private List<Record> records = new ArrayList<>();

    public static class Record {
        String filename;
        String title;
        String source;
        String link;
        String sha1;
        String date;
        String year;

        public Record(String filename, String title, String source, String link, String sha1, String date, String year) {
            this.filename = filename;
            this.title = title;
            this.source = source;
            this.link = link;
            this.sha1 = sha1;
            this.date = date;
            this.year = year;
        }

        @Override
        public String toString() {
            return "Title:   " + title + "\n" +
                   "Source:  " + source + "  |  Year: " + year + "  |  Date: " + date + "\n" +
                   "File:    " + filename + "\n" +
                   "Link:    " + link + "\n" +
                   "--------------------------------------------------------------------------------\n";
        }
    }

    public ThreatActorApp() {
        setTitle("Threat Actor Intelligence Explorer (APTnotes AWT)");
        setSize(850, 650);
        setLayout(new BorderLayout());

        // Top Panel for Search and Controls
        Panel topPanel = new Panel();
        topPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 10, 10));
        topPanel.add(new Label("Search (Title/Source/Year):"));
        
        searchField = new TextField(30);
        topPanel.add(searchField);
        
        searchButton = new Button("Search");
        topPanel.add(searchButton);

        loadAllButton = new Button("View All Records");
        topPanel.add(loadAllButton);

        add(topPanel, BorderLayout.NORTH);

        // Center Panel for Results Display (TextArea with Monospaced font)
        resultArea = new TextArea();
        resultArea.setEditable(false);
        resultArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        add(resultArea, BorderLayout.CENTER);

        // Bottom Panel for Status Bar
        Panel bottomPanel = new Panel();
        bottomPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        statusLabel = new Label("Initializing APTnotes dataset...");
        bottomPanel.add(statusLabel);
        add(bottomPanel, BorderLayout.SOUTH);

        // Event Listeners
        searchButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                performSearch(searchField.getText().trim());
            }
        });

        searchField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                performSearch(searchField.getText().trim());
            }
        });

        loadAllButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                displayAllRecords();
            }
        });

        // Window closing event
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent windowEvent) {
                System.exit(0);
            }
        });

        // Automatically load dataset on startup
        loadCsvData("APTnotes.csv");
    }

    private void loadCsvData(String filePath) {
        records.clear();
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line = br.readLine(); // Skip header row
            while ((line = br.readLine()) != null) {
                String[] parts = parseCsvLine(line);
                if (parts.length >= 7) {
                    records.add(new Record(parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]));
                }
            }
            statusLabel.setText("Successfully loaded " + records.size() + " campaign reports from " + filePath);
            displayAllRecords();
        } catch (IOException e) {
            statusLabel.setText("Error loading " + filePath + ": " + e.getMessage());
            resultArea.setText("Error: Could not locate or read 'APTnotes.csv'.\n" +
                               "Please ensure 'APTnotes.csv' is in the same directory as this compiled Java file.\n");
        }
    }

    // Basic CSV parser handling quoted fields containing commas
    private String[] parseCsvLine(String line) {
        List<String> tokens = new ArrayList<>();
        boolean inQuotes = false;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (c == ',' && !inQuotes) {
                tokens.add(sb.toString().trim());
                sb.setLength(0);
            } else {
                sb.append(c);
            }
        }
        tokens.add(sb.toString().trim());
        return tokens.toArray(new String[0]);
    }

    private void performSearch(String query) {
        if (records.isEmpty()) {
            resultArea.setText("No records available to search.");
            return;
        }
        query = query.toLowerCase();
        resultArea.setText("");
        int count = 0;
        for (Record r : records) {
            if (r.title.toLowerCase().contains(query) ||
                r.source.toLowerCase().contains(query) ||
                r.year.toLowerCase().contains(query) ||
                r.filename.toLowerCase().contains(query)) {
                resultArea.append(r.toString());
                count++;
            }
        }
        statusLabel.setText("Query '" + query + "' matched " + count + " threat intelligence record(s).");
    }

    private void displayAllRecords() {
        if (records.isEmpty()) {
            return;
        }
        resultArea.setText("");
        // Display first 100 records to maintain optimal AWT text rendering performance
        int limit = Math.min(records.size(), 100);
        for (int i = 0; i < limit; i++) {
            resultArea.append(records.get(i).toString());
        }
        statusLabel.setText("Showing first " + limit + " of " + records.size() + " total loaded campaign records.");
    }

    public static void main(String[] args) {
        EventQueue.invokeLater(new Runnable() {
            @Override
            public void run() {
                ThreatActorApp app = new ThreatActorApp();
                app.setVisible(true);
            }
        });
    }
}