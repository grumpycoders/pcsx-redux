// Exports symbols to PCSX-Redux's symbols map
//@author Nicolas "Pixel" Noble
//@category Symbol

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.*;

public class ReduxSymbols extends GhidraScript {

    public void run() throws Exception {
    	List<String> symbols = new ArrayList<String>();
        SymbolTable st = state.getCurrentProgram().getSymbolTable();
        SymbolIterator iter = st.getSymbolIterator(true);
        while (iter.hasNext() && !monitor.isCancelled()) {
            Symbol sym = iter.next();
            Address add = sym.getAddress();
            String name = sym.getName(true);
            symbols.add(String.format("%08x %s", add.getOffset(), name));
        }

    	HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:8080/api/v1/assembly/symbols"))
                .POST(HttpRequest.BodyPublishers.ofString(String.join("\n", symbols)))
                .build();

        client.send(request, HttpResponse.BodyHandlers.ofString());
    }
}
