package HTMLExtractor;

import org.json.JSONArray;
import org.json.JSONObject;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Unit test for simple App.
 */
public class HTMLExtractorTest{
	
	
	/**
	 * Test obj compare
	 */
	@Test
	public void testObjCompare()
	{
		String s1, s2;
		JSONObject o1, o2;
		
		try {
			//empty
			s1 = "{}";
			s2 = "{}";
			o1 = new JSONObject(s1);
			o2 = new JSONObject(s2);
			assertTrue( HTMLExtractor.deepCompareJSONObjects(o1, o2) );
			
			//different contents
			s1 = "{a:'asdf',b:'asdfasdf'}";
			s2 = "{a:'asdf',b:'asdf'}";
			o1 = new JSONObject(s1);
			o2 = new JSONObject(s2);
			assertFalse( HTMLExtractor.deepCompareJSONObjects(o1, o2) );
			
			//different order
			s1 = "{a:'asdf',b:'asdfasdf'}";
			s2 = "{b:'asdfasdf',a:'asdf'}";
			o1 = new JSONObject(s1);
			o2 = new JSONObject(s2);
			assertTrue( HTMLExtractor.deepCompareJSONObjects(o1, o2) );
			
			//2 deep
			s1 = "{a:{a:{a:'asdf',b:'asdfasdf'},b:'asdfasdf'},b:'asdfasdf'}";
			s2 = "{a:{a:{a:'asdf',b:'asdfasdf'},b:'asdfasdf'},b:'asdfasdf'}";
			o1 = new JSONObject(s1);
			o2 = new JSONObject(s2);
			assertTrue( HTMLExtractor.deepCompareJSONObjects(o1, o2) );
		    
			//4 deep
			s1 = "{a:{a:{a:{a:{a:'asdf',b:'asdfasdf'},b:'asdfasdf'},b:'asdfasdf'},b:'asdfasdf'},b:'asdfasdf'}";
			s2 = "{a:{a:{a:{a:{a:'asdf',b:'asdfasdf'},b:'asdfasdf'},b:'asdfasdf'},b:'asdfasdf'},b:'asdfasdf'}";
			o1 = new JSONObject(s1);
			o2 = new JSONObject(s2);
			assertTrue( HTMLExtractor.deepCompareJSONObjects(o1, o2) );
			
			//8 deep
			s1 = "{a:{a:{a:{a:"+s1+",b:'asdfasdf'},b:'asdfasdf'},b:'asdfasdf'},b:'asdfasdf'}";
			s2 = "{a:{a:{a:{a:"+s2+",b:'asdfasdf'},b:'asdfasdf'},b:'asdfasdf'},b:'asdfasdf'}";
			o1 = new JSONObject(s1);
			o2 = new JSONObject(s2);
			assertTrue( HTMLExtractor.deepCompareJSONObjects(o1, o2) );
			
			//9 deep (over the limit)
			s1 = "{a:"+s1+",b:'asdfasdf'}";
			s2 = "{a:"+s2+",b:'asdfasdf'}";
			o1 = new JSONObject(s1);
			o2 = new JSONObject(s2);
			assertFalse( HTMLExtractor.deepCompareJSONObjects(o1, o2) );
			
			//mixed types
			s1 = "{a:'asdfasdf', b:false, c:7, d:0.00001}";
			s2 = "{a:'asdfasdf', b:false, c:7, d:0.00001}";
			o1 = new JSONObject(s1);
			o2 = new JSONObject(s2);
			assertTrue( HTMLExtractor.deepCompareJSONObjects(o1, o2) );
			
			//mixed types, different content
			s1 = "{a:'asdfasdf', b:false, c:7, d:0.00000000000000001}";
			s2 = "{a:'asdfasdf', b:false, c:7, d:0.00000000000000000999999}";
			o1 = new JSONObject(s1);
			o2 = new JSONObject(s2);
			assertFalse( HTMLExtractor.deepCompareJSONObjects(o1, o2) );
			
			//including arrays
			//(and the extra whitespace should be handled by the JSONObject constructor)
			s1 = "{a:'asdfasdf', b:false, c:7, d:0.00001, e:['a','b','c','d']}";
			s2 = "{ a : 'asdfasdf', b : false, c : 7, d : 0.00001, e : ['a', 'b', 'c', 'd']}";
			o1 = new JSONObject(s1);
			o2 = new JSONObject(s2);
			assertTrue( HTMLExtractor.deepCompareJSONObjects(o1, o2) );
			
			//including non-matching arrays
			s1 = "{a:'asdfasdf', b:false, c:7, d:0.00001, e:['a','b','d','c']}";
			s2 = "{a:'asdfasdf', b:false, c:7, d:0.00001, e:['a','b','c','d']}";
			o1 = new JSONObject(s1);
			o2 = new JSONObject(s2);
			assertFalse( HTMLExtractor.deepCompareJSONObjects(o1, o2) );
			
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}

	/**
	 * Test array compare
	 */
	@Test
	public void testArrayCompare()
	{
		String s1, s2;
		JSONArray a1, a2;
		
		try {
			//empty
			s1 = "[]";
			s2 = "[]";
			a1 = new JSONArray(s1);
			a2 = new JSONArray(s2);
			assertTrue( HTMLExtractor.deepCompareJSONArrays(a1, a2) );
			
			//nested empty
			s1 = "[[[[[]]]]]";
			s2 = "[[[[[]]]]]";
			a1 = new JSONArray(s1);
			a2 = new JSONArray(s2);
			assertTrue( HTMLExtractor.deepCompareJSONArrays(a1, a2) );
			
			//different nested empty
			s1 = "[[[[[]]]]]";
			s2 = "[[[[[[]]]]]]";
			a1 = new JSONArray(s1);
			a2 = new JSONArray(s2);
			assertFalse( HTMLExtractor.deepCompareJSONArrays(a1, a2) );
			
			//nested almost too deep (outer + 8)
			s1 = "[[[[[[[[[4,3,2]]]]]]]]]";
			s2 = "[[[[[[[[[4,3,2]]]]]]]]]";
			a1 = new JSONArray(s1);
			a2 = new JSONArray(s2);
			assertTrue( HTMLExtractor.deepCompareJSONArrays(a1, a2) );
			
			//nested too deep (outer + 9)
			s1 = "[[[[[[[[[[4,3,2]]]]]]]]]]";
			s2 = "[[[[[[[[[[4,3,2]]]]]]]]]]";
			a1 = new JSONArray(s1);
			a2 = new JSONArray(s2);
			assertFalse( HTMLExtractor.deepCompareJSONArrays(a1, a2) );
			
			//matching contents
			s1 = "['asdf','asdfasdf','']";
			s2 = "['asdf','asdfasdf','']";
			a1 = new JSONArray(s1);
			a2 = new JSONArray(s2);
			assertTrue( HTMLExtractor.deepCompareJSONArrays(a1, a2) );
			
			//different contents
			s1 = "['asdf','asdfasdf']";
			s2 = "['asdf','asdfasd']";
			a1 = new JSONArray(s1);
			a2 = new JSONArray(s2);
			assertFalse( HTMLExtractor.deepCompareJSONArrays(a1, a2) );
			
			//different lengths
			s1 = "['asdf','asdfasdf']";
			s2 = "['asdf','asdfasdf','']";
			a1 = new JSONArray(s1);
			a2 = new JSONArray(s2);
			assertFalse( HTMLExtractor.deepCompareJSONArrays(a1, a2) );
			
			//different types
			s1 = "[4,'asdfasdf','',7.7, false]";
			s2 = "[4,'asdfasdf','',7.7, false]";
			a1 = new JSONArray(s1);
			a2 = new JSONArray(s2);
			assertTrue( HTMLExtractor.deepCompareJSONArrays(a1, a2) );
			
			//object types
			s1 = "[4,'asdfasdf','',7.7, false, {}, {asdf:false}, {a:'aa',b:'bb'}]";
			s2 = "[4,'asdfasdf','',7.7, false, {}, {asdf:false}, {b:'bb',a:'aa'}]";
			a1 = new JSONArray(s1);
			a2 = new JSONArray(s2);
			assertTrue( HTMLExtractor.deepCompareJSONArrays(a1, a2) );
			
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}

}