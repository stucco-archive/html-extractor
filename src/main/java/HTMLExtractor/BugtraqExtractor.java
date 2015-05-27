package HTMLExtractor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.UUID;

import java.text.*;

import org.json.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.mitre.stix.exploittarget_1.VulnerabilityType;
import org.mitre.stix.exploittarget_1.CVSSVectorType;
import org.mitre.stix.common_1.ReferencesType;
import org.mitre.stix.common_1.StructuredTextType;
import org.mitre.stix.extensions.vulnerability.CVRF11InstanceType;
import org.mitre.stix.exploittarget_1.AffectedSoftwareType;
import org.mitre.stix.common_1.DateTimeWithPrecisionType;
import org.mitre.cybox.objects.Product;
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.common_2.ObjectPropertiesType;
import org.mitre.stix.common_1.RelatedObservableType;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.stix.common_1.ReferencesType;
import org.mitre.stix.common_1.InformationSourceType;
import org.mitre.stix.common_1.ExploitTargetsType;
import org.mitre.stix.common_1.ExploitTargetBaseType;
import org.mitre.stix.exploittarget_1.ExploitTarget;
import org.mitre.cybox.common_2.TimeType;
import org.mitre.stix.stix_1.STIXHeaderType;
import org.mitre.stix.stix_1.STIXPackage;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.namespace.QName;
import javax.xml.parsers.ParserConfigurationException;

public class BugtraqExtractor extends HTMLExtractor{
	
	private JSONObject graph;
	private static final Logger logger = LoggerFactory.getLogger(BugtraqExtractor.class);

	//empty constractor for test purpose
	public BugtraqExtractor(){};

	public BugtraqExtractor(String info, String discussion, String exploit, 
			String solution, String references){
		graph = extract(info, discussion, exploit, solution, references);
	}
	
	public JSONObject getGraph() {
		return graph;
	}
	
	private long convertTimestamp(String time)	{ 
		return convertTimestamp(time + " (GMT)", "MMM dd yyyy hh:mma (z)");
	}
	
	private JSONObject extract(String info, String discussion, String exploit, 
			String solution, String references){
		
		JSONObject graph = new JSONObject();
		JSONArray vertices = new JSONArray();
		JSONArray edges = new JSONArray();
		
		JSONObject vertex = new JSONObject();
		
		//process the "info" page
		Document doc = Jsoup.parse(info);
		Element content = doc.getElementById("vulnerability");
		
		logger.debug(content.html());
		logger.debug(content.getElementsByClass("title").first().text());
		vertex.put("shortDescription", content.getElementsByClass("title").first().text());
		
		String regex = "(?s)\\s*?<td>.*?<span.*?>Bugtraq ID:</span>.*?</td>.*?<td>\\s*(.*?)\\s*</td>";
		String bugtraqID = findWithRegex(content.html(), regex, 1);
		vertex.put("name", "Bugtraq ID " + bugtraqID);
		vertex.put("_id", "Bugtraq_" + bugtraqID);
		vertex.put("_type", "vertex");
		vertex.put("vertexType", "vulnerability");
		vertex.put("source", "Bugtraq");
	    
		regex = "(?s)\\s*?<td>.*?<span.*?>Class:</span>.*?</td>.*?<td>\\s*(.*?)\\s*</td>";
	    vertex.put("class", findWithRegex(content.html(), regex, 1));
	    
	    regex = "(?s)\\s*?<td>.*?<span.*?>CVE:</span>.*?</td>.*?<td>\\s*(.*?)\\s*</td>";
	    String cve = findWithRegex(content.html(), regex, 1).replaceAll("<br\\s*/>", "");
	    vertex.put("CVE", cve);

	    regex = "(?s)\\s*?<td>.*?<span.*?>Remote:</span>.*?</td>.*?<td>\\s*(.*?)\\s*</td>";
	    String remote = findWithRegex(content.html(), regex, 1).toLowerCase().trim();
	    regex = "(?s)\\s*?<td>.*?<span.*?>Local:</span>.*?</td>.*?<td>\\s*(.*?)\\s*</td>";
	    String local = findWithRegex(content.html(), regex, 1).toLowerCase().trim();
	    if(remote.equals("yes") ){
	    	vertex.put("accessVector", "REMOTE");
	    } //if both are true, just leave as "remote" 
	    //    TODO: does this even ever happen?  if so, was this a good way to handle?
	    else if(local.equals("yes")){
	    	vertex.put("accessVector", "LOCAL");
	    }
	    else{
	    	logger.warn("unexpected accessVector for id " + bugtraqID + ": 'local' " + local + " 'remote' " + remote);
	    }
	    
	    regex = "(?s)\\s*?<td>.*?<span.*?>Published:</span>.*?</td>.*?<td>\\s*(.*?)\\s*</td>";
	    String publishedTS = findWithRegex(content.html(), regex, 1);
	    vertex.put("publishedDate", convertTimestamp(publishedTS));
	    
	    regex = "(?s)\\s*?<td>.*?<span.*?>Updated:</span>.*?</td>.*?<td>\\s*(.*?)\\s*</td>";
	    String modifiedTS = findWithRegex(content.html(), regex, 1);
	    vertex.put("modifiedDate", convertTimestamp(modifiedTS));
	    
	    regex = "(?s)\\s*?<td>.*?<span.*?>Credit:</span>.*?</td>.*?<td>\\s*(.*?)\\s*</td>";
	    vertex.put("Credit", findWithRegex(content.html(), regex, 1));

	    regex = "(?s)\\s*?<td>.*?<span.*?>Vulnerable:</span>.*?</td>.*?<td>\\s*(.*?)\\s*</td>";
	    String[] vulnerable = findWithRegex(content.html(), regex, 1).split("<br\\s*/>");
	    trimAll(vulnerable);
	    ArrayList<String> vulnerableList = new ArrayList<String>(Arrays.asList(vulnerable));
		//remove the plus and minus sub-entries.
		//see eg. http://www.securityfocus.com/bid/149/info
		String item;
		for(int i=vulnerableList.size()-1; i>=0; i--){
			item = vulnerableList.get(i);
			if(item.equals("")){
				vulnerableList.remove(i);
			}else if(item.contains("<span class=\"related\">")){
				vulnerableList.remove(i);
			}else if(item.equals("</span>")){
				vulnerableList.remove(i);
			}else if(item.contains("</span>")){
				vulnerableList.set(i, item.replaceAll("</span>\\s*", ""));
			}
		}
	    vertex.put("Vulnerable", vulnerableList);
	    
	    //add vertices and edges for the vuln software.
	    for(int i=0; i<vulnerableList.size(); i++){
	    	JSONObject v = new JSONObject();
	    	String softwareName = vulnerableList.get(i); 
	    	v.put("name", softwareName);
	    	v.put("_id", softwareName);
	    	v.put("_type", "vertex");
			v.put("vertexType", "software");
	    	v.put("source", "Bugtraq");
	    	
	    	JSONObject e = new JSONObject();
	    	String edgeName = softwareName + "_hasVulnerability_" + "Bugtraq_" + bugtraqID;
	    	e.put("_id", edgeName);
	    	String edgeDescription = softwareName + " has vulnerability " + "Bugtraq ID " + bugtraqID;
	    	e.put("description", edgeDescription);
	    	e.put("_type", "edge");
	    	e.put("inVType", "vulnerability");
	    	e.put("outVType", "software");
	    	e.put("source", "Bugtraq");
	    	e.put("_inV", "Bugtraq_" + bugtraqID);
	    	e.put("_outV", softwareName);
	    	e.put("_label", "hasVulnerability");
	    	
	    	vertices.put(v);
	    	edges.put(e);
	    }
	    
	    //not vulnerable field is rarely used, but does happen sometimes, see:
	    // http://www.securityfocus.com/bid/429/info
	    // http://www.securityfocus.com/bid/439/info
	    regex = "(?s)\\s*?<td>.*?<span.*?>Not Vulnerable:</span>.*?</td>.*?<td>\\s*(.*?)\\s*</td>";
	    String[] notVulnerable = findWithRegex(content.html(), regex, 1).split("<br\\s*/>");
	    trimAll(notVulnerable);
	    ArrayList<String> notVulnerableList = new ArrayList<String>(Arrays.asList(notVulnerable));
		//remove the plus and minus sub-entries here also.
		for(int i=notVulnerableList.size()-1; i>=0; i--){
			item = notVulnerableList.get(i);
			if(item.equals("")){
				notVulnerableList.remove(i);
			}else if(item.contains("<span class=\"related\">")){
				notVulnerableList.remove(i);
			}else if(item.equals("</span>")){
				notVulnerableList.remove(i);
			}else if(item.contains("</span>")){
				notVulnerableList.set(i, item.replaceAll("</span>\\s*", ""));
			}
		}
	    vertex.put("Not_Vulnerable", notVulnerableList);
	    
	    
		//process the "discussion" page
		doc = Jsoup.parse(discussion);
		content = doc.getElementById("vulnerability");
		vertex.put("description", content.text());
		
		
		//process the "exploit" page
		doc = Jsoup.parse(exploit);
		content = doc.getElementById("vulnerability");
		doc.getElementsByClass("title").first().remove();
		vertex.put("exploit", content.text());
		
		
		//process the "solution" page
		doc = Jsoup.parse(solution);
		content = doc.getElementById("vulnerability");
		doc.getElementsByClass("title").first().remove();
		vertex.put("solution", content.text());
	    
		
		//process the "references" page
		doc = Jsoup.parse(references);
		content = doc.getElementById("vulnerability");
		doc.getElementsByClass("title").first().remove();
		ArrayList<String> refStrings = findAllLinkHrefs(content);
		vertex.put("references", refStrings);
	    
		vertices.put(vertex);
		
		graph.put("mode","NORMAL");
		graph.put("vertices", vertices);
		graph.put("edges", edges);
		
	    return graph;
	}

				
	public STIXPackage jsonToStix (JSONObject graph)	{ 
				
		try {		
			
			GregorianCalendar calendar = new GregorianCalendar();
			JSONArray vertices = new JSONArray();
			vertices = graph.getJSONArray("vertices");			
			List<ExploitTargetBaseType> et = new ArrayList<ExploitTargetBaseType>();
																				
			for (int i = 0; i < vertices.length(); i++)	{
				VulnerabilityType vulnerability = new VulnerabilityType();
				JSONObject vertex = vertices.getJSONObject(i);
				if (vertex.getString("vertexType").equals("software")) continue;	
											
				if (vertex.has("description"))
					vulnerability
						.withDescriptions(new StructuredTextType()
							.withValue(vertex.getString("description")));
				if (vertex.has("shortDescription"))
					vulnerability							
						.withShortDescriptions(new StructuredTextType()
							.withValue(vertex.getString("shortDescription")));
				if (vertex.has("CVE"))
					vulnerability
						.withCVEID(vertex.getString("CVE"));
				if (vertex.has("source"))
					vulnerability
						.withSource(vertex.getString("source"));
				if (vertex.has("publishedDate"))	{
					calendar.setTimeInMillis(vertex.getLong("publishedDate"));
					XMLGregorianCalendar publishedDate = DatatypeFactory.newInstance().newXMLGregorianCalendar(calendar);		
					vulnerability
						.withDiscoveredDateTime(new DateTimeWithPrecisionType()
							.withValue(publishedDate)); 
				}									
				if (vertex.has("Vulnerable"))	{
					JSONArray vulnerableList = new JSONArray();
					vulnerableList = vertex.getJSONArray("Vulnerable");
					List<RelatedObservableType> relatedObservable = new ArrayList<RelatedObservableType>();
											
					for (int j = 0; j < vulnerableList.length(); j++)	{
						relatedObservable.add(new RelatedObservableType()
							.withObservable(new Observable()
								.withObject(new ObjectType()
									.withProperties(new Product()
										.withProduct(new StringObjectPropertyType()
											.withValue(vulnerableList.getString(j)))
						))));																
					}
					vulnerability
						.withAffectedSoftware(new AffectedSoftwareType()
							.withAffectedSoftwares(relatedObservable));
				}																
				if (vertex.has("references"))	{									
					ArrayList<String> references = new ArrayList<String>();
					JSONArray refJson = vertex.getJSONArray("references");
					if (refJson.length() != 0)	{
						for (int j = 0; j < refJson.length(); j++)	
							references.add(refJson.getString(j));
						vulnerability
							.withReferences(new ReferencesType()
								.withReferences(references));
					}							
				}										
				et.add(new ExploitTarget()
					.withVulnerabilities(vulnerability)
					.withId(new QName("stucco", "bugtraq-" + UUID.randomUUID().toString(), "stucco")));
															
			}								

			XMLGregorianCalendar now = DatatypeFactory.newInstance().newXMLGregorianCalendar(new GregorianCalendar(TimeZone.getTimeZone("UTC")));
			InformationSourceType producer = new InformationSourceType()
				.withTime(new TimeType()
					.withProducedTime(new org.mitre.cybox.common_2.DateTimeWithPrecisionType(now, null)));			
																		
			STIXHeaderType header = new STIXHeaderType().withTitle("Bugtraq");
			STIXPackage stixPackage = new STIXPackage()
				.withSTIXHeader(header)
				.withExploitTargets(new ExploitTargetsType()
					.withExploitTargets(et))
					.withTimestamp(now)
					.withId(new QName("stucco", "bugtraq-" + UUID.randomUUID().toString(), "stucco"));
								
			return stixPackage;			

		} catch (DatatypeConfigurationException e)	{
			e.printStackTrace();
		} 

		return null;
	}

	boolean validate(STIXPackage stixPackage) {
		return stixPackage.validate();
	}

}
