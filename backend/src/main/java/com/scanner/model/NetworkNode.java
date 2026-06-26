package com.scanner.model;

public class NetworkNode {
    private String id;
    private String label;
    private String ip;
    private String mac;
    private String vendor;
    private String os;
    private String latency;
    private String ports;
    private String risk;
    private int x;
    private int y;

    public NetworkNode() {}

    public NetworkNode(String id, String label, String ip, String mac, String vendor, String os, String latency, String ports, String risk, int x, int y) {
        this.id = id;
        this.label = label;
        this.ip = ip;
        this.mac = mac;
        this.vendor = vendor;
        this.os = os;
        this.latency = latency;
        this.ports = ports;
        this.risk = risk;
        this.x = x;
        this.y = y;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getMac() {
        return mac;
    }

    public void setMac(String mac) {
        this.mac = mac;
    }

    public String getVendor() {
        return vendor;
    }

    public void setVendor(String vendor) {
        this.vendor = vendor;
    }

    public String getOs() {
        return os;
    }

    public void setOs(String os) {
        this.os = os;
    }

    public String getLatency() {
        return latency;
    }

    public void setLatency(String latency) {
        this.latency = latency;
    }

    public String getPorts() {
        return ports;
    }

    public void setPorts(String ports) {
        this.ports = ports;
    }

    public String getRisk() {
        return risk;
    }

    public void setRisk(String risk) {
        this.risk = risk;
    }

    public int getX() {
        return x;
    }

    public void setX(int x) {
        this.x = x;
    }

    public int getY() {
        return y;
    }

    public void setY(int y) {
        this.y = y;
    }
}
