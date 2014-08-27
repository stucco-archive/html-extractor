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
		Element titleDiv = doc.getElementById("title-page-alt");
		String vertexName = titleDiv.text();
		logger.info("Name: {}", vertexName);
		vertex.put("name", vertexName);
		vertex.put("_id", vertexName);
		vertex.put("_type", "vertex");
		vertex.put("vertexType", "malware");
		vertex.put("source", "F-Secure");
		
		/////////////////////////////
		//parse the box at the top
		Element boxDiv = doc.select("div.box-rounded.br-blue").first().select("div.f-content").first();
		logger.debug(boxDiv.html());
		Element aliasDiv = boxDiv.select("div").first().select("div").get(2);
		logger.debug(aliasDiv.html());
		String[] aliasList = aliasDiv.text().split(" ");
		Set<String> aliasSet = new TreeSet<String>();
		for(String alias : aliasList){
			aliasSet.add(alias);
		}
		aliasSet.add(vertexName);
		//TODO: how best to handle aliases in the long term?
		vertex.put("aliases", new JSONArray(aliasSet));
		logger.info("Found {} items in aliasList:", aliasList.length);
		for(int i=0; i<aliasList.length; i++){
			logger.info(aliasList[i]);
		}
		
		//I think using divs as a table might actually be worse than using a table as divs...
		Element leftCatsDiv = boxDiv.select("div").first().select("div").get(3);
		logger.debug(leftCatsDiv.html());
		String[] leftCatsList = leftCatsDiv.text().replace(":","").split(" ");
		logger.info("Found {} items in leftCatsList:", leftCatsList.length);
		for(int i=0; i<leftCatsList.length; i++){
			logger.info(leftCatsList[i]);
		}

		Element rightCatsDiv = boxDiv.select("div").first().select("div").get(4);
		logger.debug(rightCatsDiv.html());
		String[] rightCatsList = rightCatsDiv.text().split(" ");
		logger.info("Found {} items in rightCatsList:", rightCatsList.length);
		for(int i=0; i<rightCatsList.length; i++){
			logger.info(rightCatsList[i]);
		}
		//make sure this is what you expected, then store fields.
		if(leftCatsList.length == 3 &&
			leftCatsList[0].equalsIgnoreCase("Category") && 
			leftCatsList[1].equalsIgnoreCase("Type") &&
			leftCatsList[2].equalsIgnoreCase("Platform"))
		{
			//keeping both fields as "malwareType", because they aren't used consistently
			JSONArray types = new JSONArray();
			types.put(rightCatsList[0]);
			types.put(rightCatsList[1]);
			vertex.put("malwareType", types);
			vertex.put("platform", rightCatsList[2]);
		}
		
		/////////////////////////
		//parse remaining page contents
		Element contentDiv = doc.select("div.content-protection").first().select("div.f-content").first();
		logger.debug(contentDiv.html());
		Elements contents = contentDiv.children().first().children();
		Element curr, prev;
		removeBRs(contents);
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
			if(curr.tagName().equals("p") && prev.tagName().equals("h3") && prev.text().equals("Technical Details")){
				vertex.put("details", curr.text());
				contents.remove(i);
				contents.remove(i-1);
				i--;
				continue;
			}
			if(curr.tagName().equals("p") && prev.tagName().equals("h3") && prev.text().equals("Summary")){
				vertex.put("overview", curr.text());
				contents.remove(i);
				contents.remove(i-1);
				i--;
				continue;
			}
			if(curr.tagName().equals("p") && prev.tagName().equals("h4") && prev.text().equals("Automatic Disinfection")){
				String removalMessage = curr.text();
				if(removalMessage.startsWith("Allow F-Secure Anti-Virus to disinfect the relevant files.")){
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
