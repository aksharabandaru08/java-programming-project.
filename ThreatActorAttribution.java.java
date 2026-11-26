import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Threat Actor Attribution Using Multi-Source Intelligence
 * Uses the supplied APTnotes CSV to rank related campaign reports.
 * Methods: Jaccard similarity and TF-IDF cosine similarity.
 * No external Java libraries are required.
 */
public class ThreatActorAttribution {
    private static final int TOP_RESULTS = 5;
    private static final double JACCARD_WEIGHT = 0.55;
    private static final double TFIDF_WEIGHT = 0.45;
    private static final double ABSTAIN_THRESHOLD = 0.06;

    private static final Set<String> STOP_WORDS = new HashSet<>(Arrays.asList((
        "a about above after again against all am an and any are as at be because been " +
        "before being below between both but by can could did do does doing down during " +
        "each few for from further had has have having he her here hers him his how i if " +
        "in into is it its itself just me more most my no nor not of off on once only or " +
        "other our ours out over own same she should so some such than that the their " +
        "them then there these they this those through to too under until up very was " +
        "we were what when where which while who why will with would you your report " +
        "analysis research security cyber attack attacks"
    ).split(" ")));

    private static class Report {
        String filename, title, source, link, sha1, date, year;
        String searchableText = "";
        Set<String> tokens = new HashSet<>();
        Map<String, Double> tfidf = new HashMap<>();

        String uniqueKey() {
            if (!safe(sha1).isBlank()) return sha1.trim().toLowerCase(Locale.ROOT);
            return (safe(title) + "|" + safe(filename)).toLowerCase(Locale.ROOT).trim();
        }
    }

    private static class Match {
        Report report;
        double jaccard, cosine, combined;
        List<String> matchedTerms;
    }

    public static void main(String[] args) {
        banner();
        try {
            Path csv = findCsv(args);
            if (csv == null) {
                System.out.println("ERROR: APTnotes CSV was not found.");
                System.out.println("Keep APTnotes.csv or APTnotes(1).csv in the same folder as this Java file.");
                return;
            }

            List<Report> reports = loadDataset(csv);
            if (reports.isEmpty()) {
                System.out.println("ERROR: The CSV contains no usable reports.");
                return;
            }
            showDatasetSummary(reports, csv);

            String incident = getIncident(args);
            if (incident == null || incident.isBlank()) {
                System.out.println("No incident description entered. Exiting.");
                return;
            }
            Set<String> queryTokens = tokenize(incident);
            if (queryTokens.isEmpty()) {
                System.out.println("No meaningful keywords found. Enter specific names or terms.");
                return;
            }

            buildTfidf(reports);
            List<Match> results = rank(reports, queryTokens);
            showResults(results, queryTokens);
            showResearchLimitations();
        } catch (IOException e) {
            System.out.println("Dataset reading error: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("Unexpected error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void banner() {
        System.out.println("==============================================================");
        System.out.println("       THREAT ACTOR ATTRIBUTION USING MULTI-SOURCE INTELLIGENCE");
        System.out.println("                    CYBER THREAT INTELLIGENCE (CTI)");
        System.out.println("==============================================================");
        System.out.println("Methods: Jaccard Similarity + TF-IDF Cosine Similarity + Ranking\n");
    }

    private static Path findCsv(String[] args) throws IOException {
        if (args.length > 0 && Files.isRegularFile(Paths.get(args[0]))) {
            return Paths.get(args[0]);
        }
        String[] names = {"APTnotes(1).csv", "APTnotes.csv", "APTnotes (1).csv"};
        for (String name : names) {
            Path p = Paths.get(name);
            if (Files.isRegularFile(p)) return p;
        }
        try (var paths = Files.list(Paths.get("."))) {
            return paths.filter(Files::isRegularFile)
                .filter(p -> p.getFileName().toString().toLowerCase(Locale.ROOT).startsWith("aptnotes"))
                .filter(p -> p.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".csv"))
                .findFirst().orElse(null);
        }
    }

    private static List<Report> loadDataset(Path csv) throws IOException {
        List<Report> reports = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        try (BufferedReader br = Files.newBufferedReader(csv, StandardCharsets.UTF_8)) {
            String headerLine = br.readLine();
            if (headerLine == null) return reports;
            if (headerLine.startsWith("\uFEFF")) headerLine = headerLine.substring(1);
            List<String> header = parseCsv(headerLine);
            Map<String, Integer> col = new HashMap<>();
            for (int i = 0; i < header.size(); i++) {
                col.put(header.get(i).trim().toLowerCase(Locale.ROOT), i);
            }
            if (!col.containsKey("title") && !col.containsKey("filename")) {
                throw new IOException("Expected Title or Filename column was not found.");
            }

            String line;
            while ((line = br.readLine()) != null) {
                if (line.isBlank()) continue;
                List<String> cells = parseCsv(line);
                Report r = new Report();
                r.filename = getCell(cells, col, "filename");
                r.title = getCell(cells, col, "title");
                r.source = getCell(cells, col, "source");
                r.link = getCell(cells, col, "link");
                r.sha1 = getCell(cells, col, "sha-1");
                r.date = getCell(cells, col, "date");
                r.year = getCell(cells, col, "year");
                if (r.title.isBlank() && r.filename.isBlank()) continue;
                if (r.year.isBlank()) r.year = extractYear(r.date);
                if (seen.add(r.uniqueKey())) reports.add(r);
            }
        }
        return reports;
    }

    // Handles commas inside quoted fields and escaped quotes in CSV rows.
    private static List<String> parseCsv(String line) {
        List<String> values = new ArrayList<>();
        StringBuilder cell = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < line.length(); i++) {
            char ch = line.charAt(i);
            if (ch == '"') {
                if (quoted && i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    cell.append('"');
                    i++;
                } else quoted = !quoted;
            } else if (ch == ',' && !quoted) {
                values.add(cell.toString());
                cell.setLength(0);
            } else cell.append(ch);
        }
        values.add(cell.toString());
        return values;
    }

    private static String getCell(List<String> cells, Map<String, Integer> col, String name) {
        Integer index = col.get(name);
        return index == null || index >= cells.size() ? "" : cells.get(index).trim();
    }

    private static String extractYear(String date) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("(19|20)\\d{2}").matcher(safe(date));
        return m.find() ? m.group() : "";
    }

    private static void showDatasetSummary(List<Report> reports, Path csv) {
        Set<String> years = reports.stream().map(r -> r.year).filter(y -> !y.isBlank())
            .collect(Collectors.toCollection(TreeSet::new));
        long sources = reports.stream().map(r -> r.source.toLowerCase(Locale.ROOT))
            .filter(s -> !s.isBlank()).distinct().count();
        System.out.println("DATASET INFORMATION");
        System.out.println("CSV file         : " + csv.toAbsolutePath());
        System.out.println("Unique reports   : " + reports.size());
        System.out.println("Distinct sources : " + sources);
        System.out.println("Year coverage    : " + (years.isEmpty() ? "Not available" : years.iterator().next() + " to " + ((TreeSet<String>) years).last()));
        System.out.println();
    }

    private static String getIncident(String[] args) {
        if (args.length > 1) return String.join(" ", Arrays.copyOfRange(args, 1, args.length));
        System.out.println("Describe the observed incident using a group, malware, country, or technique.");
        System.out.println("Example: Sandworm Ukraine energy attack Industroyer2 CaddyWiper");
        System.out.print("Incident description: ");
        Scanner input = new Scanner(System.in);
        return input.nextLine().trim();
    }

    private static Set<String> tokenize(String text) {
        Set<String> words = new LinkedHashSet<>();
        String clean = text.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", " ");
        for (String word : clean.split("\\s+")) {
            if (word.length() > 1 && !STOP_WORDS.contains(word)) words.add(word);
        }
        return words;
    }

    private static void buildTfidf(List<Report> reports) {
        Map<String, Integer> documentFrequency = new HashMap<>();
        for (Report r : reports) {
            r.searchableText = safe(r.title) + " " + safe(r.filename) + " " + safe(r.source);
            r.tokens = tokenize(r.searchableText);
            for (String token : r.tokens) documentFrequency.merge(token, 1, Integer::sum);
        }
        for (Report r : reports) {
            Map<String, Integer> termFrequency = new HashMap<>();
            String clean = r.searchableText.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", " ");
            for (String word : clean.split("\\s+")) {
                if (word.length() > 1 && !STOP_WORDS.contains(word)) termFrequency.merge(word, 1, Integer::sum);
            }
            for (Map.Entry<String, Integer> entry : termFrequency.entrySet()) {
                int df = documentFrequency.getOrDefault(entry.getKey(), 0);
                double tf = 1.0 + Math.log(entry.getValue());
                double idf = Math.log((reports.size() + 1.0) / (df + 1.0)) + 1.0;
                r.tfidf.put(entry.getKey(), tf * idf);
            }
        }
    }

    private static List<Match> rank(List<Report> reports, Set<String> query) {
        Map<String, Integer> df = new HashMap<>();
        for (Report r : reports) for (String token : r.tokens) df.merge(token, 1, Integer::sum);
        Map<String, Double> queryVector = new HashMap<>();
        for (String token : query) {
            double idf = Math.log((reports.size() + 1.0) / (df.getOrDefault(token, 0) + 1.0)) + 1.0;
            queryVector.put(token, idf);
        }

        List<Match> matches = new ArrayList<>();
        for (Report r : reports) {
            Set<String> overlap = new LinkedHashSet<>(query);
            overlap.retainAll(r.tokens);
            Set<String> union = new HashSet<>(query);
            union.addAll(r.tokens);
            Match m = new Match();
            m.report = r;
            m.jaccard = union.isEmpty() ? 0 : (double) overlap.size() / union.size();
            m.cosine = cosine(queryVector, r.tfidf);
            m.combined = JACCARD_WEIGHT * m.jaccard + TFIDF_WEIGHT * m.cosine;
            m.matchedTerms = new ArrayList<>(overlap);
            matches.add(m);
        }
        matches.sort(Comparator.comparingDouble((Match m) -> m.combined).reversed()
            .thenComparing(m -> safe(m.report.title)));
        return matches;
    }

    private static double cosine(Map<String, Double> a, Map<String, Double> b) {
        double dot = 0, normA = 0, normB = 0;
        for (double value : a.values()) normA += value * value;
        for (double value : b.values()) normB += value * value;
        for (Map.Entry<String, Double> e : a.entrySet()) dot += e.getValue() * b.getOrDefault(e.getKey(), 0.0);
        if (normA == 0 || normB == 0) return 0;
        return dot / (Math.sqrt(normA) * Math.sqrt(normB));
    }

    private static void showResults(List<Match> matches, Set<String> query) {
        System.out.println("\nINCIDENT KEYWORDS: " + String.join(", ", query));
        System.out.println("--------------------------------------------------------------");
        System.out.println("TOP MATCHING CAMPAIGN REPORTS");
        System.out.println("Similarity score is NOT a probability of attribution.");
        System.out.println("--------------------------------------------------------------");

        if (matches.isEmpty() || matches.get(0).combined < ABSTAIN_THRESHOLD) {
            System.out.println("ABSTAIN: Not enough matching text evidence was found.");
            System.out.println("Try adding a specific malware name, group, operation, or location.");
            return;
        }

        int count = 0;
        for (Match m : matches) {
            if (count == TOP_RESULTS || m.combined <= 0) break;
            count++;
            Report r = m.report;
            System.out.printf("\n[%d] %s%n", count, r.title.isBlank() ? r.filename : r.title);
            System.out.printf(Locale.ROOT, "    Combined similarity : %.2f%%%n", m.combined * 100);
            System.out.printf(Locale.ROOT, "    Jaccard similarity  : %.2f%%%n", m.jaccard * 100);
            System.out.printf(Locale.ROOT, "    TF-IDF cosine       : %.2f%%%n", m.cosine * 100);
            System.out.println("    Source              : " + (r.source.isBlank() ? "Not specified" : r.source));
            System.out.println("    Year / Date         : " + (r.year.isBlank() ? "Not specified" : r.year)
                + (r.date.isBlank() ? "" : " / " + r.date));
            System.out.println("    Matched keywords    : " + (m.matchedTerms.isEmpty() ? "None" : String.join(", ", m.matchedTerms)));
            System.out.println("    Report link         : " + (r.link.isBlank() ? "Not available" : r.link));
        }
        System.out.println("\nBest textual match: " + safe(matches.get(0).report.title));
        System.out.println("This ranking finds related reports for analyst review; it does not prove who performed the incident.");
    }

    private static void showResearchLimitations() {
        System.out.println("\nRESEARCH NOTES");
        System.out.println("1. Jaccard similarity measures overlap between incident and report keywords.");
        System.out.println("2. TF-IDF cosine similarity highlights informative terms in report metadata.");
        System.out.println("3. Combined score = 55% Jaccard + 45% TF-IDF cosine similarity.");
        System.out.println("4. The supplied APTnotes CSV contains report metadata, not complete report text.");
        System.out.println("5. It does not contain verified actor labels or structured MITRE ATT&CK techniques.");
        System.out.println("6. Weak evidence is handled by abstaining instead of making a definitive attribution.");
        System.out.println("==============================================================");
        System.out.println("                 ANALYSIS COMPLETED SUCCESSFULLY");
        System.out.println("==============================================================");
    }

    private static String safe(String value) {
        return value == null ? "" : value.trim();
    }
}
