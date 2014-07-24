package HTMLExtractor;

import java.util.ArrayList;
import java.util.Arrays;

import org.json.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

public class BugtraqTestDataExtractor extends HTMLExtractor{
	
	private JSONObject graph;

	public BugtraqTestDataExtractor(String info, String discussion, String exploit, 
			String solution, String references){
		graph = extract(info, discussion, exploit, solution, references);
	}
	
	public JSONObject getGraph() {
		return graph;
	}
	
	private long convertTimestamp(String time)	{ 
		return convertTimestamp(time, "MMM dd yyyy hh:mma");
	}
	
	private JSONObject extract(String info, String discussion, String exploit, 
			String solution, String references){
		
		JSONObject vertex = new JSONObject();
		
		//process the "info" page
		Document doc = Jsoup.parse(info);
		Element content = doc.getElementById("vulnerability");
		
		//System.out.println(content.html());
		//System.out.println(content.getElementsByClass("title").first().text());
		vertex.put("shortDescription", content.getElementsByClass("title").first().text());
		
		String regex = "(?s)\\s*?<td>.*?<span.*?>Bugtraq ID:</span>.*?</td>.*?<td>\\s*(.*?)\\s*</td>";
	    vertex.put("name", findWithRegex(content.html(), regex, 1));
	    
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
	    
		JSONObject graph = new JSONObject();
		JSONArray vertices = new JSONArray();
		JSONArray edges = new JSONArray();
		vertices.put(vertex);
		
		graph.put("mode","NORMAL");
		graph.put("vertices", vertices);
		graph.put("edges", edges);
		
	    return graph;
	}

}
