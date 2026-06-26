package com.scanner.model;

public class IdsAlert {
    private long id;
    private String time;
    private String source;
    private String type;
    private String severity;
    private String desc;
    private String rec;

    public IdsAlert() {}

    public IdsAlert(long id, String time, String source, String type, String severity, String desc, String rec) {
        this.id = id;
        this.time = time;
        this.source = source;
        this.type = type;
        this.severity = severity;
        this.desc = desc;
        this.rec = rec;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getTime() {
        return time;
    }

    public void setTime(String time) {
        this.time = time;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getDesc() {
        return desc;
    }

    public void setDesc(String desc) {
        this.desc = desc;
    }

    public String getRec() {
        return rec;
    }

    public void setRec(String rec) {
        this.rec = rec;
    }
}
