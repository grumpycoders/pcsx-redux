// Exports symbols to PCSX-Redux's symbols map including Overlays filtering
//@author Nicolas "Pixel" Noble
//@author acemon33

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
        List<String> options = this.getMemoryBlockOptions();
        List<String> filterList = askChoices("Title", "Message", options);
        List<String> choiceList = this.getOptionList(options);
        
        List<String> symbols = new ArrayList<String>();
        SymbolTable st = state.getCurrentProgram().getSymbolTable();
        SymbolIterator iter = st.getSymbolIterator(true);
        while (iter.hasNext() && !monitor.isCancelled()) {
            Symbol sym = iter.next();
            Address add = sym.getAddress();
            String name = sym.getName(true);
            
            boolean hasFilter = true;
            for (String s : filterList) {
                if (add.toString().contains(s)) {
                    hasFilter = false;
                    break;
                }
            }
            if (hasFilter)
            {
                boolean isNext = false;
                for (String s : choiceList) {
                    if (add.toString().contains(s)) {
                        isNext = true;
                        break;
                    }
                }
                if (isNext)
                    continue;
            }

            symbols.add(String.format("%08x %s", add.getOffset(), name));
            // symbols.add(String.format("%s %s", add, name));
            // println(String.format("%s %s", add, name));
        }

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:8080/api/v1/assembly/symbols?function=upload"))
                .POST(HttpRequest.BodyPublishers.ofString(String.join("\n", symbols)))
                .build();

        client.send(request, HttpResponse.BodyHandlers.ofString());
    
        // for (String address : symbols) println(address);
        println("size: " + symbols.size());
    }

    private List<String> getMemoryBlockOptions() {
        MemoryBlock[] MemoryBlockList = state.getCurrentProgram().getMemory().getBlocks();
        List<String> options = new ArrayList();
        for (int i = 0; i < MemoryBlockList.length; i++) {
            if (MemoryBlockList[i].isOverlay())
                options.add(MemoryBlockList[i].getName());
        }
        return options;
    }

    private List<String> getOptionList(List<String> options) {
        List<String> resultList = new ArrayList();
        for (String e : options) {
            resultList.add(e + "::");
            resultList.add(e + "__");
            }
        return resultList;
    }
}
