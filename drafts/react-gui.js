// ############### Some parameters ###############

var baseUrl = 'http://127.0.0.1:2080';
var analyseUrl = '/api/v1/testcase_analyse';
var dissectUrl = '/api/v1/frames_dissect';
var getTestCasesUrl = '/api/v1/get_testcases';
var getProtocolsUrl = '/api/v1/get_protocols';



// ############### Utility functions ###############
function checkError(errorTrigger, data) {

	// Check the datas received
	if (data && !data.ok && data.type == 'error') {

		// Clear the error message displayer
		$('#error-modal .modal-body .alert').html(
			'<button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>'
		);

		// The error message to display
		var errorMessage = 'An error occured';

		// Check if we have the error trigger
		if (errorTrigger != '') errorMessage += ' during ' + errorTrigger;

		// Check the data we have
		if (data.value != '') errorMessage += '<br/><br/>More informations:</br>' + data.value;
		
		// Display the error itself in a bootstrap model
		$('#error-modal .modal-body .alert').append(errorMessage);
		$('#error-modal').modal('show');
	}
}


// ############### React code ###############

// A renderer for the radio buttons
var RadioButton = React.createClass({

	/**
	 * Render function for InputGroupBloc
	 */
	render: function() {
		var selected = (this.props.currentAction == this.props.inputValue);
		return (
			<label className={ (selected) ? 'btn btn-info active' : 'btn btn-info' } onClick={this.props.switchAction} value={this.props.inputValue} >
				<input type="radio" checked={selected} id={this.props.inputValue} name={this.props.inputName} value={this.props.inputValue} onChange={function(){}} /> {this.props.inputText}
			</label>
		);
	}
});



// A renderer for the input groups
var InputGroupBloc = React.createClass({

	/**
	 * Render function for InputGroupBloc
	 */
	render: function() {

		// If addon on right
		if (this.props.textOnLeft) return (
			<div className="input-group">
				<span className="input-group-addon">{this.props.addonText}</span>
				<input type={this.props.inputType} className="form-control" name={this.props.inputName} placeholder={this.props.inputPlaceholder} required={this.props.required} />
			</div>
		);

		// If addon on left
		else return (
			<div className="input-group">
				<input type={this.props.inputType} className="form-control" name={this.props.inputName} placeholder={this.props.inputPlaceholder} required={this.props.required} />
				<span className="input-group-addon">{this.props.addonText}</span>
			</div>
		);
	}
});



// A renderer for the select group
var SelectGroupBloc = React.createClass({

	/**
	 * Render function for InputGroupBloc
	 */
	render: function() {

		// Analyse action
		if (this.props.currentAction == 'analyse') {
			var optionInputName = 'testcase_id';
			var optionAddonText = 'Test case';

			// Check the result
			if (this.props.optionGroups && this.props.optionGroups.ok && this.props.optionGroups.type == 'testcase_list') {
				return (
					<div className="input-group">
						<span className="input-group-addon" >{optionAddonText}</span>
						<select name="testcase_id" className="form-control">
							{
								this.props.optionGroups.value.map(function(tc){
									return (
										<option key={tc.name} value={tc.name} title={tc.description} >{tc.name}</option>
									);
								})
							}
						</select>
					</div>
				);

			// An error occured
			} else {
				console.log('ERROR: Couldn\'t retrieve the list of test cases');
				if (this.props.optionGroups && !this.props.optionGroups.ok && this.props.optionGroups.type == 'error')
					console.log('More informations: ' + this.props.optionGroups.value);
				return null;
			}
		}

		// Dissect action
		else {

			var optionInputName = 'protocol_selection';
			var optionAddonText = 'Protocol';

			// Check the result
			if (this.props.optionGroups && this.props.optionGroups.ok && this.props.optionGroups.type == 'protocol_list') {
				return (
					<div className="input-group">
						<span className="input-group-addon" >{optionAddonText}</span>
						<select name="testcase_id" className="form-control">
							{
								this.props.optionGroups.value.map(function(tc){
									return (
										<option key={tc.name} value={tc.name} title={tc.description} >{tc.name}</option>
									);
								})
							}
						</select>
					</div>
				);

			// An error occured
			} else {
				console.log('ERROR: Couldn\'t retrieve the list of protocols');
				if (this.props.optionGroups && !this.props.optionGroups.ok && this.props.optionGroups.type == 'error')
					console.log('More informations: ' + this.props.optionGroups.value);
				return null;
			}
		}
	}
});



// The FormBloc renderer
var FormBloc = React.createClass({

	/**
	 * Handler for the submit of the form
	 */
	handlePcapSubmit: function(form) {

		// Bloc the "real" submit of the form, instead use this function
		form.preventDefault();
		var url = form.currentTarget.action;

		// Send the post request in ajax
		$.ajax({
			url: url,
			type: 'POST',
			processData: false,
			contentType: 'multipart/form-data',
			data: [],
			success: function(data) {
				checkError('POST request on ' + url, data);
			}.bind(this),
			error: function(xhr, status, err) {
				console.error(this.props.url, status, err.toString());
			}.bind(this)
		});
	},


	/**
	 * Handler for when the user change the action (dissect or analyse)
	 */
	switchAction: function(optionChoosed) {
		this.setState({action: optionChoosed.currentTarget.value});
	},


	/**
	 * Function thrown after the element is fully loaded
	 */
	componentDidMount: function() {

		// Get the list of test cases from the server
		$.ajax({
			url: this.props.baseUrl + getTestCasesUrl,
			dataType: 'json',
			success: function(data) {
				checkError('the fetching the test cases', data);
				this.setState({testCases: data});
			}.bind(this),
			error: function(xhr, status, err) {
				console.error(this.props.url, status, err.toString());
			}.bind(this)
		});

		// Get the list of protocols from the server
		$.ajax({
			url: this.props.baseUrl + getProtocolsUrl,
			dataType: 'json',
			success: function(data) {
				checkError('the fetching the protocols', data);
				this.setState({protocols: data});
			}.bind(this),
			error: function(xhr, status, err) {
				console.error(this.props.url, status, err.toString());
			}.bind(this)
		});
	},


	/**
	 * Getter of the initial state for parameters
	 */
	getInitialState: function() {
		return {
			action: 'analyse',
			testCases: {ok: false},
			protocols: {ok: false}
		};
	},


	/**
	 * Render function for FormBloc
	 */
	render: function() {

		// The things that will change in the view in function of the current action
		if (this.state.action == 'analyse') {
			var url = this.props.baseUrl + analyseUrl;
			var optionsTitle = 'Analysis options';
			var selectOptions = <SelectGroupBloc currentAction={this.state.action} optionGroups={this.state.testCases} />;
		} else {
			var url = this.props.baseUrl + dissectUrl;
			var optionsTitle = 'Dissection options';
			var selectOptions =<SelectGroupBloc currentAction={this.state.action} optionGroups={this.state.protocols} />;
		}

		// console.log(this.state.testCases);
		
		var fileTitle = 'Pcap field to ' + this.state.action;

		return (
			<form action={url} method="post" enctype="multipart/form-data" onSubmit={this.handlePcapSubmit} >

				<div className="row">
					<div className="col-sm-6">
						<div className="page-header">
							<h1>{fileTitle}</h1>
						</div>
						<InputGroupBloc inputName="pcap" inputType="file" addonText="Enter your pcap file" required={true} textOnLeft={true} inputPlaceholder="" />
					</div>

					<div className="col-sm-6">
						<div className="page-header">
							<h1>{optionsTitle}</h1>
						</div>

						{selectOptions}

						<div style={{textAlign: 'center'}}>
							<div className="btn-group" data-toggle="buttons" >
								<RadioButton inputName="options" inputValue="analyse" inputText="Analyse" currentAction={this.state.action} switchAction={this.switchAction} />
								<RadioButton inputName="options" inputValue="dissect" inputText="Dissect" currentAction={this.state.action} switchAction={this.switchAction} />
							</div>
						</div>
					</div>
				</div>

				<div className="row">
					<p style={{textAlign: 'center'}}>
						<input type="submit" value="Execute" className="btn btn-success centered-block" />
					</p>
				</div>
			</form>
		);
	}
});


// The PcapUtility renderer
var PcapUtility = React.createClass({

	/**
	 * Render function for PcapForm
	 */
	render: function() {
		return (
			<div className="row">
				<FormBloc baseUrl={baseUrl} />

				<div className="modal fade" role="dialog" id="error-modal">
					<div className="modal-dialog">
						<div className="modal-content">
							<div className="modal-body">
								<div className="alert alert-danger">
									<button type="button" className="close" data-dismiss="modal" aria-label="Close">
										<span aria-hidden="true">&times;</span>
									</button>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		);
	}
});



ReactDOM.render(
	<PcapUtility />,
	document.getElementById('content')
);