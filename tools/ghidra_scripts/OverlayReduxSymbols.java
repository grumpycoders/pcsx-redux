// Exports symbols to PCSX-Redux's symbols map including Overlays filtering
//@author acemon33
//@category PSX

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.*;

public class OverlayReduxSymbols extends GhidraScript {

    public void run() throws Exception {
        MemoryBlock[] MemoryBlockList = state.getCurrentProgram().getMemory().getBlocks();
        List<String> choices = new ArrayList();
        for (int i = 0; i < MemoryBlockList.length; i++) { if (MemoryBlockList[i].isOverlay()) choices.add(MemoryBlockList[i].getName()); }
        List<String> filterList = askChoices("Title", "Message", choices);
        List<String> choiceList = new ArrayList();
        for (String e : choices) { choiceList.add(e + "::"); choiceList.add(e + "__"); }
        
        List<String> symbols = new ArrayList<String>();
        SymbolTable st = state.getCurrentProgram().getSymbolTable();
        SymbolIterator iter = st.getSymbolIterator(true);
        while (iter.hasNext() && !monitor.isCancelled()) {
            Symbol sym = iter.next();
            Address add = sym.getAddress();
            String name = sym.getName(true);
            
            boolean hasFilter = true;
            for (String s : filterList) { if (add.toString().contains(s)) { hasFilter = false; break; } }
            if (hasFilter)
            {
                boolean isNext = false;
                for (String s : choiceList) { if (add.toString().contains(s)) { isNext = true; break; } }
                if (isNext) continue;
            }

            symbols.add(String.format("%08x %s", add.getOffset(), name));
        }

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:8080/api/v1/assembly/symbols?function=upload"))
                .POST(HttpRequest.BodyPublishers.ofString(String.join("\n", symbols)))
                .build();

        client.send(request, HttpResponse.BodyHandlers.ofString());
    
        println("size: " + symbols.size());
    }
}
