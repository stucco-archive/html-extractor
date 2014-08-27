package HTMLExtractor;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.*;

import org.json.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Attributes;
import org.jsoup.nodes.Element;
import org.jsoup.parser.Tag;
import org.jsoup.select.Elements;

public abstract class HTMLExtractor {

	private static int MAX_COMPARE_DEPTH = 8;
	
	protected static String findWithRegex(String content, String regex){
		return findWithRegex(content, regex, 1);
	}
	
	protected static String findWithRegex(String content, String regex, int groupNum){
		Pattern pattern = Pattern.compile(regex);
	    Matcher matcher = pattern.matcher(content);
	    matcher.find();
		return matcher.group(1);
	}

	protected static void trimAll(String[] items) {
		for(int i=0; i<items.length; i++){
	    	items[i] = items[i].trim();
	    }
	}
	
	protected static void removeBRs(Elements contents){
		Element curr;
		for(int i = contents.size()-1; i>=0; i--){
			curr = contents.get(i);
			if(curr.tagName().equals("br")){
				contents.remove(i);
				continue;
			}
		}
	}
	
	//NB: assumes dt and dd are one-to-one (will skip ones that aren't)
	//NB: also assumes that dt and dd tags have text()-able content.
	protected Map<String, String> dlToMap(Element dl) {
		HashMap<String, String> retMap = new HashMap<String, String>();
		if( dl.tagName().equals("dl") ){
			Elements terms = dl.getElementsByTag("dt");
			Element currTerm, currDef;
			for(int i=0; i<terms.size(); i++){
				currTerm = terms.get(i);
				currDef = currTerm.nextElementSibling();
				if(currDef != null && currDef.tagName().equals("dd")){
					retMap.put(currTerm.text(), currDef.text());
				}
			}
			return retMap;	
		}
		else return null;
	}
	
	//NB: assumes that the li tags have (cleanly) text()-able content.
	protected Set<String> ulToSet(Element ul) {
		TreeSet<String> retSet = new TreeSet<String>();
		if( ul.tagName().equals("ul") ){
			Elements items = ul.getElementsByTag("li");
			Element currItem;
			for(int i=0; i<items.size(); i++){
				currItem = items.get(i);
				retSet.add(currItem.text());
			}
			return retSet;
		}
		else return null;
	}
	
	//NB: this will leave some empty grandchild-level tags around, but children will still be cleanly text()-able
	//TODO: revisit above.
	protected Element removeGrandchildren(Element parent) {
		Elements children = parent.children();
		Elements grandchildren;
		for(int i=0; i<children.size(); i++){
			grandchildren = children.get(i).children();
			for(int j=0; j<grandchildren.size(); j++){
				grandchildren.get(j).empty();
			}
		}
		return parent;
	}
	
	//NB: JSON array must be array of strings
	protected Set<String> JSONArrayToSet(JSONArray arr) {
		TreeSet<String> retSet = new TreeSet<String>();
		if(arr != null){
			for(int i=0; i<arr.length(); i++){
				retSet.add(arr.getString(i));
			}
		}
		return retSet;
	}
	
	protected long convertTimestamp(String time, String format)	{ 
		Date date = new Date();
		try {
			SimpleDateFormat df = new SimpleDateFormat(format);
  			date = df.parse(time);
  			return date.getTime();	

		} catch	(ParseException e)	{
			e.printStackTrace();
		}
  		return date.getTime();	
	}
	
	protected ArrayList<String> findAllLinkHrefs(Element content) {
		Elements refs = content.select("a[href]");
		ArrayList<String> hrefStrings = new ArrayList<String>();
		String hrefString = "";
		for(int i=0; i<refs.size(); i++){
			hrefString = refs.get(i).attr("href");
			hrefStrings.add(hrefString);
		}
		//System.out.println(refs);
		//System.out.println(refStrings);
		return hrefStrings;
	}
	
	public static boolean deepCompareJSONObjects(JSONObject obj1, JSONObject obj2){
		return deepCompareJSONObjects(obj1, obj2, 0);
	}
	
	private static boolean deepCompareJSONObjects(JSONObject obj1, JSONObject obj2, int currDepth){
		boolean retVal = true;
		//System.out.println("depth: " + currDepth);
		if(currDepth <= MAX_COMPARE_DEPTH){
			Set<String> obj1keys = obj1.keySet();
			Set<String> obj2keys = obj2.keySet();
			if(obj1keys.equals(obj2keys)){
				for(String k : obj1keys){
					if(!retVal) continue;
					//check if an obj...
					JSONObject o1 = obj1.optJSONObject(k);
					JSONObject o2 = obj2.optJSONObject(k);
					if(o1 != null && o2 != null){
						retVal = retVal && deepCompareJSONObjects(o1, o2, currDepth+1);
						continue;
					}
					
					//or try as an array...
					JSONArray a1 = obj1.optJSONArray(k);
					JSONArray a2 = obj2.optJSONArray(k);
					if(a1 != null && a2 != null){
						retVal = retVal && deepCompareJSONArrays(a1, a2, currDepth+1);
						continue;
					}
					
					//or just get as strings and compare
					String s1 = obj1.optString(k);
					String s2 = obj2.optString(k);
					retVal = retVal && s1.equals(s2);
				}
			}
			else{//keys don't match, so fail.
				retVal = false;
			}
		}
		else{//over the limit, so fail.
			retVal = false;
		}
		return retVal;
	}
	
	public static boolean deepCompareJSONArrays(JSONArray arr1, JSONArray arr2){
		return deepCompareJSONArrays(arr1, arr2, 0);
	}
	
	private static boolean deepCompareJSONArrays(JSONArray arr1, JSONArray arr2, int currDepth){
		boolean retVal = true;
		//System.out.println("depth: " + currDepth);
		if(currDepth <= MAX_COMPARE_DEPTH){
			if(arr1.length() == arr2.length()){
				for(int i=0; i<arr1.length() && retVal; i++){
					//check if an obj...
					JSONObject o1 = arr1.optJSONObject(i);
					JSONObject o2 = arr2.optJSONObject(i);
					if(o1 != null && o2 != null){
						retVal = retVal && deepCompareJSONObjects(o1, o2, currDepth+1);
						continue;
					}
					
					//or try as an array...
					JSONArray a1 = arr1.optJSONArray(i);
					JSONArray a2 = arr2.optJSONArray(i);
					if(a1 != null && a2 != null){
						retVal = retVal && deepCompareJSONArrays(a1, a2, currDepth+1);
						continue;
					}
					
					//or just get as strings and compare
					String s1 = arr1.optString(i);
					String s2 = arr2.optString(i);
					retVal = retVal && s1.equals(s2);
				}
			}
			else{//length doesn't match, so fail.
				retVal = false;
			}
		}
		else{//over the limit, so fail.
			retVal = false;
		}
		return retVal;
	}
	
}
