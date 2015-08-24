package HTMLExtractor;

import java.util.List;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;

import org.json.*;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

import org.jsoup.parser.Parser;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.junit.Test;

import static org.junit.Assert.*;

import HTMLExtractor.DNSRecordExtractor;

/**
 * Unit test for DNSRecord Extractor.
 */
public class DNSRecordExtractorTest extends HTMLExtractor {
	
	/**
	 * Test one element
	 */
	@Test
	public void test_one_element_with_header()	{

		try {
			String headers = 
				"filename,recnum,file_type,amp_version,site,saddr,daddr,ttl,rqtype,flags,rqfqdn,refqdn,raddr,preference," +	
				"answer_ns,authoritative_ns,times_seen,first_seen_timet,last_seen_timet,scountrycode,sorganization,slat,slong," +
				"dcountrycode,dorganization,dlat,dlong,rcountrycode,rorganization,rlat,rlong";
			String[] HEADERS = headers.split(",");
			String dnsInfo = 
				"filename,recnum,file_type,amp_version,site,saddr,daddr,ttl,rqtype,flags,rqfqdn,refqdn,raddr,preference," +	
				"answer_ns,authoritative_ns,times_seen,first_seen_timet,last_seen_timet,scountrycode,sorganization,slat,slong," +
				"dcountrycode,dorganization,dlat,dlong,rcountrycode,rorganization,rlat,rlong\n" +
				"20150712000033-ornl-ampDnsN4-1,42513,3,258,ornl,128.219.177.244,68.87.73.245,0,1,17,DALE-PC.ORNL.GOV,,,,,5n6unsmlboh476,2," +
				"2015-07-12 00:00:27+00,2015-07-12 00:00:27+00,US,oak ridge national laboratory,36.02103,84,US,comcast cable communications inc.," +	
				"38.6741,-77.4243,..,..,-91,-181";
		
			DNSRecordExtractor dnsExtractor = new DNSRecordExtractor(dnsInfo);
			JSONObject graph = dnsExtractor.getGraph().getJSONArray("vertices").getJSONObject(0); 
			CSVFormat csvFormat = CSVFormat.DEFAULT.withHeader(HEADERS);
			Reader reader = new StringReader(dnsInfo);
			CSVParser csvParser = new CSVParser(reader, csvFormat);
			List<CSVRecord> records = csvParser.getRecords();
			CSVRecord csv = records.get(1);

			System.out.println("Testing DNSName vertex");
			assertEquals(graph.get("_id"), csv.get("rqfqdn"));
			assertEquals(graph.get("name"), csv.get("rqfqdn"));
			assertEquals(graph.get("description"), csv.get("rqfqdn"));
			assertEquals(graph.get("_type"), "vertex");
			assertEquals(graph.get("vertexType"), "DNSName");
			assertEquals(graph.get("source"), "DNSRecord");
			assertEquals(graph.get("ns1"), csv.get("authoritative_ns"));
		
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Test two elements
	 */
	@Test
	public void test_two_elements_no_header()	{
	
		try {
			String headers = 
				"filename,recnum,file_type,amp_version,site,saddr,daddr,ttl,rqtype,flags,rqfqdn,refqdn,raddr,preference," +	
				"answer_ns,authoritative_ns,times_seen,first_seen_timet,last_seen_timet,scountrycode,sorganization,slat,slong," +
				"dcountrycode,dorganization,dlat,dlong,rcountrycode,rorganization,rlat,rlong";
			String[] HEADERS = headers.split(",");
			String dnsInfo = 
				"20150712000225-ornl-ampDnsA4-1,7016,2,258,ornl,199.7.83.42,160.91.86.22,172800,1,3,a.in-addr-servers.arpa,,199.212.0.73,,,," +	
				"2015-07-12 00:00:01+00,2015-07-12 00:00:01+00,US,icann,34.0634,-118.2393,US,oak ridge national laboratory,36.02103,-84.25273,zzz" +	
				"US,arin operations,38.90825,-77.51781\n" +
				"20150712000225-ornl-ampDnsA4-1,2903,2,258,ornl,172.26.2.16,160.91.19.22,86400,1,209,ornl.gov,,160.91.5.21,,," +
				"dns1.ornl.gov,dns2.ornl.gov,1,2015-07-12 00:01:51+00,2015-07-12 00:01:51+00,..,..,-91,-181,US,oak ridge national laboratory," +
				"36.02103,-84.25273,US,oak ridge national laboratory,36.02103,-84.25273";
			
			DNSRecordExtractor dnsExtractor = new DNSRecordExtractor(dnsInfo);
			JSONObject graph = dnsExtractor.getGraph();
			JSONArray vertices = graph.getJSONArray("vertices"); 
			JSONArray edges = graph.getJSONArray("edges"); 

			CSVFormat csvFormat = CSVFormat.DEFAULT.withHeader(HEADERS);
			Reader reader = new StringReader(dnsInfo);
			CSVParser csvParser = new CSVParser(reader, csvFormat);
			List<CSVRecord> records = csvParser.getRecords();
			
			for (int i = 0; i < records.size(); i++) {
				CSVRecord csv = records.get(i);
				
				if (!csv.get("rqfqdn").isEmpty()) {
					boolean match = false;
					for (int j = 0; j < vertices.length(); j++) {
						JSONObject v = vertices.getJSONObject(j);
						if (v.getString("name").equals(csv.get("rqfqdn"))) {
							System.out.println("Testing DNSName vertex");
							assertEquals(v.get("_id"), csv.get("rqfqdn"));
							assertEquals(v.get("name"), csv.get("rqfqdn"));
							assertEquals(v.get("description"), csv.get("rqfqdn"));
							assertEquals(v.get("_type"), "vertex");
							assertEquals(v.get("vertexType"), "DNSName");
							assertEquals(v.get("source"), "DNSRecord");
							if (!csv.get("authoritative_ns").isEmpty()) {
								assertEquals(v.get("ns1"), csv.get("authoritative_ns"));
							}
							if (!csv.get("answer_ns").isEmpty()) {
								assertEquals(v.get("ns2"), csv.get("answer_ns"));
							}
							match = true;
						}
					}
					if (!match) {
						System.out.println("ERROR: Cannot find DNSName vertex " + csv.get("rqfqdn"));
					}
				}
				if (!csv.get("raddr").isEmpty()) {
					boolean match = false;
					for (int j = 0; j < vertices.length(); j++) {
						JSONObject v = vertices.getJSONObject(j);
						if (v.getString("name").equals(csv.get("raddr"))) {
							System.out.println("Testing IP vertex");
							assertEquals(v.get("_id"), csv.get("raddr"));
							assertEquals(v.get("name"), csv.get("raddr"));
							assertEquals(v.get("description"), csv.get("raddr"));
							assertEquals(v.get("_type"), "vertex");
							assertEquals(v.get("vertexType"), "IP");
							assertEquals(v.get("source"), "DNSRecord");
							match = true;
						}
					}
					if (!match) {
						System.out.println("ERROR: Cannot find IP vertex " + csv.get("raddr"));
					}
				}
				if (!csv.get("rqfqdn").isEmpty() && !csv.get("raddr").isEmpty()) {
					System.out.println("Testing DNSName to IP edge");
					boolean match = false;
					for (int j = 0; j < edges.length(); j++) {
						JSONObject e = edges.getJSONObject(j);
						if (e.getString("_outV").equals(csv.get("rqfqdn")) && e.getString("_inV").equals(csv.get("raddr"))) {
							assertEquals(e.get("_id"), csv.get("rqfqdn") + "_hasIp_" + csv.get("raddr"));
							assertEquals(e.get("description"), csv.get("rqfqdn") + " has IP " + csv.get("raddr"));
							assertEquals(e.get("_type"), "edge");
							assertEquals(e.get("inVType"), "IP");
							assertEquals(e.get("outVType"), "DNSName");
							assertEquals(e.get("source"), "DNSRecord");
							assertEquals(e.get("_inV"), csv.get("raddr"));
							assertEquals(e.get("_outV"), csv.get("rqfqdn"));
							assertEquals(e.get("_label"), "hasIP");
							match = true;
						}
					}
					if (!match) {
						System.out.println("ERROR: Cannot find edge from DNSName " + csv.get("rqfqdn") + " to IP " + csv.get("raddr"));
					}
				}
			}

		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
