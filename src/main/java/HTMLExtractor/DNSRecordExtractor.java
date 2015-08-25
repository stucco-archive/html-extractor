package HTMLExtractor;

import java.util.List;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;

import org.json.*;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * DNS record extractor.
 *
 * @author Maria Vincent
 */
public class DNSRecordExtractor extends HTMLExtractor {
						
	private static final Logger logger = LoggerFactory.getLogger(DNSRecordExtractor.class);
	private static String[] HEADERS = {"filename", "recnum", "file_type", "amp_version", "site", "saddr", "daddr", "ttl", "rqtype", "flags", "rqfqdn",
					   "refqdn", "raddr", "preference", "answer_ns", "authoritative_ns", "times_seen", "first_seen_timet", "last_seen_timet", 
					   "scountrycode", "sorganization", "dcountrycode", "dorganization", "rcountrycode", "rorganization"};
	private static final String FILENAME = "filename";
	private static final String RQFQDN = "rqfqdn";	
	private static final String RADDR = "raddr";	
	private static final String ANSWER_NS = "answer_ns";	
	private static final String AUTHORITATIVE_NS = "authoritative_ns";	
	
	private JSONObject graph;

	public DNSRecordExtractor(String dnsInfo) {
		graph = extract(dnsInfo);
	}

	public JSONObject getGraph() {
		return graph;
	}
	
	private JSONObject extract(String dnsInfo) {
		try {
			JSONObject graph = new JSONObject();
			JSONArray vertices = new JSONArray();
			JSONArray edges = new JSONArray();

			CSVFormat csvFormat = CSVFormat.DEFAULT.withHeader(HEADERS);
			Reader reader = new StringReader(dnsInfo);
			CSVParser csvParser = new CSVParser(reader, csvFormat);
			List<CSVRecord> records = csvParser.getRecords();

			if (records.isEmpty()) {
				return null;
			}

			CSVRecord record = records.get(0);
			int start;

			/* computing a start of iteration */
			if (record.get(0).equals(FILENAME))	{
				if (record.size() == 1)	{
					return null;
				} else {
					start = 1;
				}
			} else {
				start = 0;
			}		
		 	
			for (int i = start; i < records.size(); i++) {

				record = records.get(i);
				
				JSONObject dns = null;
				JSONObject ip = null;
				JSONObject dnsToIp = null;
				
				/* dns vertex */
				if (!record.get(RQFQDN).isEmpty()) {
					dns = new JSONObject();
					dns.put("_id", record.get(RQFQDN));	
					dns.put("name", record.get(RQFQDN));	
					dns.put("description", record.get(RQFQDN));	
					dns.put("_type", "vertex");	
					dns.put("vertexType", "DNSName");	
					dns.put("source", "DNSRecord");	
					if (!record.get(AUTHORITATIVE_NS).isEmpty()) {
						dns.put("ns1", record.get(AUTHORITATIVE_NS));	
					}
					if (!record.get(ANSWER_NS).isEmpty()) {
						dns.put("ns1", record.get(ANSWER_NS));	
					}
					vertices.put(dns);
				}

				/* ip vertex */
				if (!record.get(RADDR).isEmpty()) {
					ip = new JSONObject();
					ip.put("_id", record.get(RADDR));
					ip.put("name", record.get(RADDR));
					ip.put("description", record.get(RADDR));
					ip.put("_type", "vertex");
					ip.put("vertexType", "IP");
					ip.put("source", "DNSRecord");
					vertices.put(ip);
				}

				/* dns to ip edge */
				if (dns != null && ip != null) {
					dnsToIp = new JSONObject();
					dnsToIp.put("_id", record.get(RQFQDN) + "_hasIp_" + record.get(RADDR));
					dnsToIp.put("description", record.get(RQFQDN) + " has IP " + record.get(RADDR));
					dnsToIp.put("_type", "edge");
					dnsToIp.put("inVType", "IP");
					dnsToIp.put("outVType", "DNSName");
					dnsToIp.put("source", "DNSRecord");
					dnsToIp.put("_inV", record.get(RADDR));
					dnsToIp.put("_outV", record.get(RQFQDN));
					dnsToIp.put("_label", "hasIP");
					edges.put(dnsToIp);
				}
			}

			if (vertices.length() != 0) {
				graph.put("vertices", vertices);
			}
			if (edges.length() != 0) {
				graph.put("edges", edges);
			}
				
			return (graph.length() ==0 ) ? null : graph;

		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}
}
