package org.raspigateway.demo;

import java.io.File;
import java.io.IOException;

import org.pytorch.executorch.extension.llm.LlmCallback;
import org.pytorch.executorch.extension.llm.LlmModule;

final class LocalReportExplainer {
    private static final int MAX_SEQUENCE_LENGTH = 384;

    static String explain(File filesDir, Reports.Report report) throws IOException {
        File instructModel = new File(filesDir, "llama-instruct.pte");
        File instructTokenizer = new File(filesDir, "llama-instruct.model");
        boolean instruct = available(instructModel) && available(instructTokenizer);
        File model = instruct ? instructModel : new File(filesDir, "llama-base.pte");
        File tokenizer = instruct ? instructTokenizer : new File(filesDir, "llama-base.model");
        if (!available(model) || !available(tokenizer)) {
            throw new IOException("Local model files are missing. Run prepare-model.sh with your phone connected.");
        }
        String prompt = ReportPrompt.format(report, instruct);
        StringBuilder output = new StringBuilder();
        LlmModule module = new LlmModule(model.getAbsolutePath(), tokenizer.getAbsolutePath(), 0.0f);
        try {
            int status = module.load();
            if (status != 0) throw new IOException("Model loading failed (code " + status + ").");
            module.generate(prompt, MAX_SEQUENCE_LENGTH, new LlmCallback() {
                @Override public void onResult(String token) {
                    output.append(token);
                }

                @Override public void onStats(String stats) {}
            }, false);
        } finally {
            module.resetNative();
        }
        String answer = output.toString().trim();
        if (!ReportPrompt.isUsable(answer)) {
            throw new IOException("The model did not produce a readable explanation.");
        }
        return answer;
    }

    private static boolean available(File file) {
        return file.isFile() && file.canRead() && file.length() > 0;
    }
}
