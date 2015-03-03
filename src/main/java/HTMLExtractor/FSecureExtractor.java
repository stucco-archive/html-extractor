package HTMLExtractor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;

import org.json.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.parser.Tag;
import org.jsoup.select.Elements;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FSecureExtractor extends HTMLExtractor{
	
	private JSONObject graph;
	private static final Logger logger = LoggerFactory.getLogger(FSecureExtractor.class);
	
	public FSecureExtractor(String pageContent){
		graph = extract(pageContent);
	}
	
	public JSONObject getGraph() {
		return graph;
	}
	
	//TODO: get timestamp from RSS?
	//private long convertTimestamp(String time)	{ 
	//}
	
	//This makes <p><b> text into <h4> text.
	//They are equivalent, but not used consistently between pages.
	private static void fixSectionHeaders(Elements contents){
		Element curr, replacement;
		Elements currChildren;
		for(int i = contents.size()-1; i>=0; i--){
			curr = contents.get(i);
			if(curr.tagName().equals("p")){
				currChildren = curr.children();
				if(currChildren.size() == 1 && currChildren.get(0).tagName().equalsIgnoreCase("b")){
					replacement = new Element(Tag.valueOf("h4"), "");
					replacement.text(curr.text());
					contents.remove(i);
					contents.add(i, replacement);
				}
			}
		}
	}
	
	private JSONObject extract(String pageContent){
		
		JSONObject graph = new JSONObject();
		JSONArray vertices = new JSONArray();
		JSONArray edges = new JSONArray();
		
		JSONObject vertex = new JSONObject();
		
		Document doc = Jsoup.parse(pageContent);
		
		////////////////////////////////////
		//get the title, set up name & other known fields
		String vertexName = doc.getElementsByTag("title").first().text().replaceAll("\u200b", "").replaceAll("\\:\\?",":");
		
		
		logger.info("Name: {}", vertexName);
		vertex.put("name", vertexName);
		vertex.put("_id", vertexName);
		vertex.put("_type", "vertex");
		vertex.put("vertexType", "malware");
		vertex.put("source", "F-Secure");

		/////////////////////////////
		//parse the box at the top
		Element detailsTable = doc.getElementsByClass("details-table").first();
		String[][] cells = getCells(detailsTable.getElementsByTag("tr"));
		
		logger.debug("table contains: {}", new JSONArray(cells));
		
		String aliases = cells[0][1];
		String category = cells[1][1];
		String type = cells[2][1];
		String platform = cells[3][1];
		
		String[] aliasList = aliases.split(", ");
		logger.debug("Found {} items in aliasList:", aliasList.length);
		for(int i=0; i<aliasList.length; i++){
			logger.debug(aliasList[i]);
		}
		Set<String> aliasSet = new TreeSet<String>();
		for(String alias : aliasList){
			aliasSet.add(alias.replaceAll("\u200b", "").replaceAll("\\:\\?",":"));
		}
		aliasSet.add(vertexName);
		JSONArray aliasesResult = new JSONArray(aliasSet);
		logger.info("final alias list is: {}", aliasesResult);
		vertex.put("aliases", aliasesResult);
		//TODO: how best to handle aliases in the long term?
		
		//keeping both fields as "malwareType", because they aren't used consistently
		JSONArray types = new JSONArray();
		types.put(category);
		types.put(type);
		vertex.put("malwareType", types);
		vertex.put("platform", platform);
		

		/////////////////////////
		//parse remaining page contents
		Element contentDiv = doc.select("div#maincontent").first().select("div.row").first().select("div").first();
		logger.debug(contentDiv.html());
		Elements contents = contentDiv.children().first().children();
		Element curr, prev;
		removeBRs(contents);
		removeHRs(contents);
		fixSectionHeaders(contents);
		logger.debug(contents.outerHtml());
		//System.out.println("contents size is now: " + contents.size());
		for(int i = contents.size()-1; i>0; i--){
			curr = contents.get(i);
			prev = contents.get(i-1);
			//System.out.println(i + ":::" + prev.text() + ":::" + curr.text());
			//merge paragraphs, etc...
			if(curr.tagName().equals("p") && prev.tagName().equals("p")){
				prev.text( prev.text() + "\n" + curr.text() );
				contents.remove(i);
				continue;
			}
			if(curr.tagName().equals("p") && prev.tagName().equals("ul")){
				curr.text( ulToString(prev) + "\n" + curr.text() );
				contents.remove(i-1);
				continue;
			}
			if(curr.tagName().equals("p") && prev.tagName().equals("img")){
				//TODO
				curr.text( prev.attr("src") + "\n" + curr.text() );
				contents.remove(i-1);
				continue;
			}
			//pull out expected fields, based on headers...
			if(curr.tagName().equals("p") && prev.tagName().equals("h2") && prev.text().equals("Technical Details")){
				vertex.put("details", curr.text());
				contents.remove(i);
				contents.remove(i-1);
				i--;
				continue;
			}
			if(curr.tagName().equals("p") && prev.tagName().equals("h2") && prev.text().equals("Summary")){
				vertex.put("description", curr.text());
				contents.remove(i);
				contents.remove(i-1);
				i--;
				continue;
			}
			if(curr.tagName().equals("p") && prev.tagName().equals("h5") && prev.text().equals("Automatic action")){
				String removalMessage = curr.text();
				if(removalMessage.startsWith("Once detected, the F-Secure security product will automatically disinfect the suspect file")){
					vertex.put("removal", "F-Secure");
				}else{
					vertex.put("removal", "F-Secure: " + removalMessage);
				}
				contents.remove(i);
				contents.remove(i-1);
				contents.remove(i-2);
				i -= 2;
				continue;
			}
			if(curr.tagName().equals("p") && prev.tagName().equals("h4") && prev.text().equals("Distribution")){
				vertex.put("distribution", curr.text());
				contents.remove(i);
				contents.remove(i-1);
				i -= 1;
				continue;
			}
			if(curr.tagName().equals("p") && prev.tagName().equals("h4") && prev.text().equals("Behavior")){
				vertex.put("behavior", curr.text());
				contents.remove(i);
				contents.remove(i-1);
				i -= 1;
				continue;
			}
			if(curr.tagName().equals("p") && (prev.tagName().equals("h5") || prev.tagName().equals("h4")) && prev.text().equals("More")){
				//Don't put contents anywhere for these, just ignore.
				contents.remove(i);
				contents.remove(i-1);
				i -= 1;
				continue;
			}
		}
		
		//having remaining text is somewhat common with these entries...
		logger.info("=====REMAINING:=====");
		logger.info(contents.outerHtml());
		logger.info("=========");
        
		vertices.put(vertex);
		
		graph.put("mode","NORMAL");
		graph.put("vertices", vertices);
		graph.put("edges", edges);
		
	    return graph;
	}

	private static String ulToString(Element ul){
		String ret;
		ret = ul.text();
		logger.debug(":::ulToString is returning::: {}", ret);
		return ret;
	}
}
