package HTMLExtractor;

import java.util.ArrayList;
import java.util.Arrays;

import org.json.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BugtraqExtractor extends HTMLExtractor{
	
	private JSONObject graph;
	private static final Logger logger = LoggerFactory.getLogger(BugtraqExtractor.class);

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
	    String vertexName = "Bugtraq_" + findWithRegex(content.html(), regex, 1);
		vertex.put("name", vertexName);
		vertex.put("_id", vertexName);
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
	    	vertex.put("accessVector", "Remote");
	    } //if both are true, just leave as "remote" 
	    //    TODO: does this even ever happen?  if so, was this a good way to handle?
	    else if(local.equals("yes")){
	    	vertex.put("accessVector", "Local");
	    }
	    else{
	    	vertex.put("accessVector", "Other");
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
			if(item.contains("<span class=\"related\">")){
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
	    	String edgeName = softwareName + "_to_" + vertexName;
	    	e.put("_id", edgeName);
	    	e.put("_type", "edge");
	    	e.put("inVType", "vulnerability");
	    	e.put("outVType", "software");
	    	e.put("source", "Bugtraq");
	    	e.put("_inV", vertexName);
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
			if(item.contains("<span class=\"related\">")){
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

}
