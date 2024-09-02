# A Standard Chronicle Query for Incident Response

## Understanding the Basics

In incident response, a typical Chronicle query involves filtering events based on specific criteria—such as time, event type, or process/file details. Below is a basic example:

```sql
SELECT *  
FROM events  
WHERE event.type = 'PROCESS_CREATED'  
AND event.process.name = 'suspicious_process'  
AND event.timestamp BETWEEN '2024-09-01' AND '2024-09-02'
```

### What This Query Does:
- **The event type is** `PROCESS_CREATED`.  
- **The process name is** `suspicious_process`.  
- **The event occurred between** September 1st and 2nd, 2024.

---

## Breaking Down the Components:

- **`SELECT *`**: Selects all fields in the `events` table. Specify individual fields if needed.
- **`FROM events`**: Queries the `events` table, which contains the raw security data.
- **`WHERE`**: Filters the results based on conditions.
  - **`event.type = 'PROCESS_CREATED'`**: Filters for process creation events.
  - **`event.process.name = 'suspicious_process'`**: Filters for a specific process name.
  - **`event.timestamp BETWEEN '2024-09-01' AND '2024-09-02'`**: Filters for events within a specific time range.

---

## Example: Investigating a Data Exfiltration Incident

If you suspect a data exfiltration incident, you can use a more complex query like this:

```sql
SELECT *  
FROM events  
WHERE (event.type = 'NETWORK_CONNECTION' OR event.type = 'FILE_CREATED')  
AND (event.network.remote_ip = '192.168.1.100' OR event.file.path LIKE '%sensitive_data%')  
AND event.timestamp BETWEEN '2024-08-25' AND '2024-09-02'
```

### What This Query Does:
- **Filters events related to network connections or file creation** involving a specific IP address or file path.
- **Looks within the time range** between August 25th and September 2nd, 2024.

---

## Advanced Techniques:

- **Regular Expressions**: Leverage regular expressions for more complex pattern matching.
- **Aggregations**: Use functions like `COUNT()`, `SUM()`, and `AVG()` to aggregate data.
- **Custom Fields**: Integrate custom fields into your queries if they exist in your Chronicle environment.
- **Joining Tables**: Combine data across multiple tables using joins.

This version is more structured, visually separated, and includes highlights for easier reading and understanding.

# Google Chronicle Queries

Google Chronicle deployments typically feature consistent field names, thanks to Chronicle's standardized, cloud-based security analytics platform. While minor variations may exist depending on specific integrations or customer configurations, the core fields used for common events—such as process creation, file creation, and network connections—remain largely uniform.

### Common Key Fields in Chronicle:
- **`event.type`**: Represents the event type (e.g., `PROCESS_CREATED`, `FILE_CREATED`, `NETWORK_CONNECTION`).
- **`host.hostname`**: The hostname of the affected system.
- **`event.process.name`**: The name of the process involved.
- **`event.file.path`**: The path of the file involved.
- **`event.network.remote_ip`**: The IP address of the remote system involved.

---

### Best Practices for Querying in Chronicle

1. **Validate Field Names**:  
   Before using a query, verify that the specific field names exist in your Chronicle deployment. Running a simple query like:
   ```SQL
   SELECT * FROM events LIMIT 10
   ```
   can help you inspect the available fields and confirm accuracy.

2. **Incorporate Custom Fields**:  
   If your Chronicle environment includes custom fields (e.g., from integrations or data enrichment), be sure to incorporate them into your queries appropriately.

# IR Queries

## Malware/PUA/PUP prevalance by hostname
   ```SQL
SELECT host.hostname, COUNT(*) AS incident_count
FROM events
WHERE (event.type = "PROCESS_CREATED" OR event.type = "FILE_CREATED" OR event.type = "NETWORK_CONNECTION")
AND (event.process.name LIKE "%YOUR_MALWARE_INDICATOR%" OR event.file.path LIKE "%YOUR_MALWARE_INDICATOR%")
GROUP BY host.hostname
ORDER BY incident_count DESC
   ```
