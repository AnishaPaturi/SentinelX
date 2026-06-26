package com.scanner.service;

import com.lowagie.text.*;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import com.scanner.model.ScanResult;
import com.scanner.repository.ScanResultRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.awt.Color;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Service
public class ReportService {

    @Autowired
    private ScanResultRepository scanResultRepository;

    public ByteArrayInputStream generatePdfReport(String host) {
        List<ScanResult> results = scanResultRepository.findByHost(host);
        
        Document document = new Document(PageSize.A4);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        try {
            PdfWriter.getInstance(document, out);
            document.open();

            // Font styles
            Font titleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 22, Color.DARK_GRAY);
            Font subtitleFont = FontFactory.getFont(FontFactory.HELVETICA, 12, Color.GRAY);
            Font headingFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 14, Color.BLACK);
            Font bodyFont = FontFactory.getFont(FontFactory.HELVETICA, 10, Color.BLACK);
            Font boldBodyFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10, Color.BLACK);

            // Document Header
            Paragraph title = new Paragraph("Network Vulnerability Scan Report", titleFont);
            title.setAlignment(Element.ALIGN_CENTER);
            title.setSpacingAfter(5);
            document.add(title);

            Paragraph date = new Paragraph("Generated on: " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")), subtitleFont);
            date.setAlignment(Element.ALIGN_CENTER);
            date.setSpacingAfter(20);
            document.add(date);

            // Executive Summary
            document.add(new Paragraph("1. Executive Summary", headingFont));
            document.add(Chunk.NEWLINE);
            
            int openPortsCount = results.size();
            long criticalVuls = results.stream().filter(r -> "CRITICAL".equalsIgnoreCase(r.getRiskLevel())).count();
            long highVuls = results.stream().filter(r -> "HIGH".equalsIgnoreCase(r.getRiskLevel())).count();
            
            String summaryText = String.format("A security audit scan was performed on host %s. A total of %d open ports were identified. " +
                    "The assessment identified %d CRITICAL and %d HIGH severity vulnerabilities. Immediate mitigation steps are recommended for any highlighted items.",
                    host, openPortsCount, criticalVuls, highVuls);
            document.add(new Paragraph(summaryText, bodyFont));
            document.add(Chunk.NEWLINE);

            // Findings Table
            document.add(new Paragraph("2. Vulnerability Findings", headingFont));
            document.add(Chunk.NEWLINE);

            PdfPTable table = new PdfPTable(5);
            table.setWidthPercentage(100);
            table.setWidths(new float[]{1.5f, 2.0f, 3.0f, 3.5f, 2.0f});

            // Headers
            String[] headers = {"Port", "Service", "Banner", "Identified Risks", "Risk Level"};
            for (String header : headers) {
                PdfPCell cell = new PdfPCell(new Phrase(header, FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10, Color.WHITE)));
                cell.setBackgroundColor(new Color(157, 78, 221)); // Purple accent matching React dashboard!
                cell.setPadding(6);
                cell.setHorizontalAlignment(Element.ALIGN_CENTER);
                table.addCell(cell);
            }

            // Populate scan records
            for (ScanResult result : results) {
                table.addCell(new Phrase(String.valueOf(result.getPort()), bodyFont));
                table.addCell(new Phrase(result.getService(), bodyFont));
                table.addCell(new Phrase(result.getBanner() != null ? result.getBanner() : "N/A", bodyFont));
                
                // Construct risk description from banner/service
                String riskDesc = "No major risks identified.";
                String serviceLower = result.getService().toLowerCase();
                String bannerLower = result.getBanner() != null ? result.getBanner().toLowerCase() : "";
                
                if (serviceLower.equals("telnet") || serviceLower.equals("ftp")) {
                    riskDesc = "Unencrypted credentials transmission.";
                } else if (bannerLower.contains("apache/2.2") || bannerLower.contains("cve-2017-5638")) {
                    riskDesc = "Known CVE-2017-5638 RCE Vulnerability.";
                } else if (bannerLower.contains("openssh/7.2")) {
                    riskDesc = "Known CVE-2016-6210 Information Leak.";
                } else if (bannerLower.contains("mysql 5.5")) {
                    riskDesc = "CVE-2012-2122 Security Authentication Bypass.";
                }
                table.addCell(new Phrase(riskDesc, bodyFont));

                // Risk level styling cell
                PdfPCell riskCell = new PdfPCell();
                Phrase riskPhrase = new Phrase(result.getRiskLevel(), boldBodyFont);
                riskCell.addElement(riskPhrase);
                if ("CRITICAL".equalsIgnoreCase(result.getRiskLevel())) {
                    riskCell.setBackgroundColor(new Color(255, 230, 230));
                } else if ("HIGH".equalsIgnoreCase(result.getRiskLevel())) {
                    riskCell.setBackgroundColor(new Color(255, 240, 220));
                } else if ("MEDIUM".equalsIgnoreCase(result.getRiskLevel())) {
                    riskCell.setBackgroundColor(new Color(255, 255, 220));
                } else {
                    riskCell.setBackgroundColor(new Color(230, 255, 230));
                }
                riskCell.setPadding(6);
                riskCell.setHorizontalAlignment(Element.ALIGN_CENTER);
                table.addCell(riskCell);
            }

            document.add(table);
            document.add(Chunk.NEWLINE);

            // Recommendations Section
            document.add(new Paragraph("3. Recommendations & Next Steps", headingFont));
            document.add(Chunk.NEWLINE);

            if (criticalVuls > 0 || highVuls > 0) {
                document.add(new Paragraph("• Discontinue plain-text protocols (Telnet/FTP) immediately and switch to secure alternatives like SSH (SFTP).", bodyFont));
                document.add(new Paragraph("• Update services with critical vulnerabilities (e.g. Upgrade Apache to version 2.4.x or above).", bodyFont));
                document.add(new Paragraph("• Configure host-based firewall settings (iptables/firewalld) to filter inbound traffic on unrequired management ports.", bodyFont));
            } else {
                document.add(new Paragraph("• Maintain regular schedule-based vulnerability scans.", bodyFont));
                document.add(new Paragraph("• Keep internal software and OS distributions updated to their latest stable patches.", bodyFont));
            }

            document.close();

        } catch (Exception e) {
            e.printStackTrace();
        }

        return new ByteArrayInputStream(out.toByteArray());
    }
}
