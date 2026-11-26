import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import java.util.Scanner;
import java.util.TreeMap;


public class CyberThreatTimelineAnalyzer {
    private static final String FILE_NAME = "APTnotes.csv";
    private static final ArrayList<ThreatReport> reports = new ArrayList<>();
    private static final Scanner scanner = new Scanner(System.in);

    static class ThreatReport {
        String filename;
        String title;
        String source;
        String link;
        String sha1;
        String date;
        int year;

        ThreatReport(String filename, String title, String source,
                     String link, String sha1, String date, int year) {
            this.filename = filename;
            this.title = title;
            this.source = source;
            this.link = link;
            this.sha1 = sha1;
            this.date = date;
            this.year = year;
        }
    }

    public static void main(String[] args) {
        printWelcome();

        if (!loadDataset()) {
            System.out.println("Program cannot continue.");
            scanner.close();
            return;
        }

        boolean running = true;

        while (running) {
            displayMenu();
            int choice = readInteger("Enter your choice: ");

            switch (choice) {
                case 1:
                    displayAllReports();
                    break;
                case 2:
                    displayYearlyStatistics();
                    break;
                case 3:
                    displayBusiestYear();
                    break;
                case 4:
                    searchByYear();
                    break;
                case 5:
                    searchByTitle();
                    break;
                case 6:
                    searchBySource();
                    break;
                case 7:
                    displayDatasetSummary();
                    break;
                case 8:
                    filterByYearRange();
                    break;
                case 9:
                    System.out.println("Thank you for using the analyzer!");
                    running = false;
                    break;
                default:
                    System.out.println("Invalid choice. Try again.");
            }

            if (running) {
                System.out.println();
                System.out.println("Press Enter to return to the menu.");
                scanner.nextLine();
            }
        }

        scanner.close();
    }

    private static void printWelcome() {
        System.out.println("========================================");
        System.out.println("     CYBER THREAT TIMELINE ANALYZER");
        System.out.println("========================================");
        System.out.println("APT Report Dataset Analysis System");
        System.out.println("----------------------------------------");
    }

    private static void displayMenu() {
        System.out.println();
        System.out.println("============== MAIN MENU ==============");
        System.out.println("1. Display all reports");
        System.out.println("2. Year-wise report statistics");
        System.out.println("3. Find busiest and least busy year");
        System.out.println("4. Search reports by year");
        System.out.println("5. Search reports by title");
        System.out.println("6. Search reports by source");
        System.out.println("7. Display dataset summary");
        System.out.println("8. Filter reports by year range");
        System.out.println("9. Exit");
        System.out.println("=======================================");
    }

    private static boolean loadDataset() {
        File file = new File(FILE_NAME);

        if (!file.exists()) {
            System.out.println("ERROR: APTnotes.csv was not found.");
            System.out.println("Place the CSV file beside the Java file.");
            return false;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String headerLine = reader.readLine();

            if (headerLine == null) {
                System.out.println("The dataset is empty.");
                return false;
            }

            ArrayList<String> headers = parseCSVLine(headerLine);
            int filenameIndex = findColumn(headers, "Filename");
            int titleIndex = findColumn(headers, "Title");
            int sourceIndex = findColumn(headers, "Source");
            int linkIndex = findColumn(headers, "Link");
            int shaIndex = findColumn(headers, "SHA-1");
            int dateIndex = findColumn(headers, "Date");
            int yearIndex = findColumn(headers, "Year");

            if (titleIndex == -1 || yearIndex == -1) {
                System.out.println("Required CSV columns are missing.");
                return false;
            }

            String line;

            while ((line = reader.readLine()) != null) {
                if (line.trim().isEmpty()) {
                    continue;
                }

                ArrayList<String> fields = parseCSVLine(line);
                String filename = getField(fields, filenameIndex);
                String title = getField(fields, titleIndex);
                String source = getField(fields, sourceIndex);
                String link = getField(fields, linkIndex);
                String sha1 = getField(fields, shaIndex);
                String date = getField(fields, dateIndex);
                int year = parseYear(getField(fields, yearIndex));

                if (year > 0 && !title.isEmpty()) {
                    reports.add(new ThreatReport(filename, title, source,
                            link, sha1, date, year));
                }
            }

            System.out.println();
            System.out.println("Dataset loaded successfully!");
            System.out.println("Valid reports loaded: " + reports.size());
            return !reports.isEmpty();
        } catch (IOException exception) {
            System.out.println("Error reading dataset: " + exception.getMessage());
            return false;
        }
    }

    private static int findColumn(ArrayList<String> headers, String columnName) {
        for (int i = 0; i < headers.size(); i++) {
            if (headers.get(i).trim().equalsIgnoreCase(columnName)) {
                return i;
            }
        }
        return -1;
    }

    private static String getField(ArrayList<String> fields, int index) {
        if (index < 0 || index >= fields.size()) {
            return "";
        }
        return fields.get(index).trim();
    }

    private static int parseYear(String value) {
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException exception) {
            return -1;
        }
    }

    private static ArrayList<String> parseCSVLine(String line) {
        ArrayList<String> fields = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean insideQuotes = false;

        for (int i = 0; i < line.length(); i++) {
            char character = line.charAt(i);

            if (character == '"') {
                if (insideQuotes && i + 1 < line.length()
                        && line.charAt(i + 1) == '"') {
                    current.append('"');
                    i++;
                } else {
                    insideQuotes = !insideQuotes;
                }
            } else if (character == ',' && !insideQuotes) {
                fields.add(current.toString());
                current.setLength(0);
            } else {
                current.append(character);
            }
        }

        fields.add(current.toString());
        return fields;
    }

    private static void displayAllReports() {
        System.out.println();
        System.out.println("========== ALL REPORTS ==========");

        if (reports.isEmpty()) {
            System.out.println("No reports available.");
            return;
        }

        int count = 0;

        for (ThreatReport report : reports) {
            count++;
            System.out.println();
            System.out.println("Report Number: " + count);
            displayReportDetails(report);
        }

        System.out.println();
        System.out.println("Total displayed: " + count);
    }

    private static void displayReportDetails(ThreatReport report) {
        System.out.println("Filename : " + report.filename);
        System.out.println("Title    : " + report.title);
        System.out.println("Source   : " + report.source);
        System.out.println("Date     : " + report.date);
        System.out.println("Year     : " + report.year);
        System.out.println("Link     : " + report.link);
        System.out.println("SHA-1    : " + report.sha1);
    }

    private static TreeMap<Integer, Integer> calculateYearCounts() {
        TreeMap<Integer, Integer> counts = new TreeMap<>();

        for (ThreatReport report : reports) {
            int year = report.year;
            counts.put(year, counts.getOrDefault(year, 0) + 1);
        }

        return counts;
    }

    private static void displayYearlyStatistics() {
        System.out.println();
        System.out.println("======= YEAR-WISE STATISTICS =======");
        TreeMap<Integer, Integer> counts = calculateYearCounts();

        if (counts.isEmpty()) {
            System.out.println("No yearly data available.");
            return;
        }

        for (Map.Entry<Integer, Integer> entry : counts.entrySet()) {
            System.out.println(entry.getKey() + " : "
                    + entry.getValue() + " reports");
        }

        System.out.println("------------------------------------");
        System.out.println("Number of different years: " + counts.size());
    }

    private static void displayBusiestYear() {
        System.out.println();
        System.out.println("======= YEAR ANALYSIS =======");
        TreeMap<Integer, Integer> counts = calculateYearCounts();

        if (counts.isEmpty()) {
            System.out.println("No data available.");
            return;
        }

        int maximum = Integer.MIN_VALUE;
        int minimum = Integer.MAX_VALUE;

        for (int count : counts.values()) {
            maximum = Math.max(maximum, count);
            minimum = Math.min(minimum, count);
        }

        System.out.println("Busiest year(s):");

        for (Map.Entry<Integer, Integer> entry : counts.entrySet()) {
            if (entry.getValue() == maximum) {
                System.out.println(entry.getKey() + " with "
                        + maximum + " reports");
            }
        }

        System.out.println();
        System.out.println("Least busy year(s):");

        for (Map.Entry<Integer, Integer> entry : counts.entrySet()) {
            if (entry.getValue() == minimum) {
                System.out.println(entry.getKey() + " with "
                        + minimum + " reports");
            }
        }
    }

    private static void searchByYear() {
        System.out.println();
        System.out.println("======= SEARCH BY YEAR =======");
        int year = readInteger("Enter year to search: ");
        int found = 0;

        for (ThreatReport report : reports) {
            if (report.year == year) {
                found++;
                System.out.println();
                System.out.println("Result " + found);
                displayReportDetails(report);
            }
        }

        System.out.println();
        System.out.println("Total matching reports: " + found);
    }

    private static void searchByTitle() {
        System.out.println();
        System.out.println("======= SEARCH BY TITLE =======");
        System.out.print("Enter title or keyword: ");
        String keyword = scanner.nextLine().trim().toLowerCase();
        int found = 0;

        for (ThreatReport report : reports) {
            if (report.title.toLowerCase().contains(keyword)) {
                found++;
                System.out.println();
                System.out.println("Result " + found);
                displayReportDetails(report);
            }
        }

        if (found == 0) {
            System.out.println("No matching title found.");
        }

        System.out.println("Total results: " + found);
    }

    private static void searchBySource() {
        System.out.println();
        System.out.println("======= SEARCH BY SOURCE =======");
        System.out.print("Enter source name or keyword: ");
        String keyword = scanner.nextLine().trim().toLowerCase();
        int found = 0;

        for (ThreatReport report : reports) {
            if (report.source.toLowerCase().contains(keyword)) {
                found++;
                System.out.println();
                System.out.println("Result " + found);
                System.out.println("Title: " + report.title);
                System.out.println("Source: " + report.source);
                System.out.println("Year: " + report.year);
            }
        }

        if (found == 0) {
            System.out.println("No reports found for this source.");
        }

        System.out.println("Total matching reports: " + found);
    }

    private static void displayDatasetSummary() {
        System.out.println();
        System.out.println("======= DATASET SUMMARY =======");

        if (reports.isEmpty()) {
            System.out.println("Dataset contains no reports.");
            return;
        }

        TreeMap<Integer, Integer> counts = calculateYearCounts();
        int earliestYear = counts.firstKey();
        int latestYear = counts.lastKey();
        int totalReports = reports.size();

        System.out.println("Dataset file: " + FILE_NAME);
        System.out.println("Total reports: " + totalReports);
        System.out.println("Earliest report year: " + earliestYear);
        System.out.println("Latest report year: " + latestYear);
        System.out.println("Years represented: " + counts.size());

        double average = (double) totalReports / counts.size();
        System.out.printf("Average reports per year: %.2f%n", average);
        displaySourceCount();
    }

    private static void displaySourceCount() {
        HashSet<String> sources = new HashSet<>();

        for (ThreatReport report : reports) {
            if (!report.source.isEmpty()) {
                sources.add(report.source);
            }
        }

        System.out.println("Different source names: " + sources.size());
    }

    private static void filterByYearRange() {
        System.out.println();
        System.out.println("======= YEAR RANGE FILTER =======");
        int startYear = readInteger("Enter starting year: ");
        int endYear = readInteger("Enter ending year: ");

        if (startYear > endYear) {
            System.out.println("Starting year cannot exceed ending year.");
            return;
        }

        int found = 0;

        for (ThreatReport report : reports) {
            if (report.year >= startYear && report.year <= endYear) {
                found++;
                System.out.println();
                System.out.println("Result " + found);
                System.out.println("Title: " + report.title);
                System.out.println("Source: " + report.source);
                System.out.println("Year: " + report.year);
            }
        }

        System.out.println();
        System.out.println("Reports in selected range: " + found);
    }

    private static int countReportsForYear(int year) {
        int count = 0;

        for (ThreatReport report : reports) {
            if (report.year == year) {
                count++;
            }
        }

        return count;
    }

    private static ThreatReport findReportByTitle(String title) {
        for (ThreatReport report : reports) {
            if (report.title.equalsIgnoreCase(title)) {
                return report;
            }
        }

        return null;
    }

    private static int readInteger(String message) {
        while (true) {
            System.out.print(message);
            String input = scanner.nextLine().trim();

            try {
                return Integer.parseInt(input);
            } catch (NumberFormatException exception) {
                System.out.println("Please enter a valid whole number.");
            }
        }
    }
}
